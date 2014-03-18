/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

/***************************************************************************
 * Copyright (C) 2013-2014 Ping Identity Corporation
 * All rights reserved.
 *
 * The contents of this file are the property of Ping Identity Corporation.
 * For further information please contact:
 *
 *      Ping Identity Corporation
 *      1099 18th St Suite 2950
 *      Denver, CO 80202
 *      303.468.2900
 *      http://www.pingidentity.com
 *
 * DISCLAIMER OF WARRANTIES:
 *
 * THE SOFTWARE PROVIDED HEREUNDER IS PROVIDED ON AN "AS IS" BASIS, WITHOUT
 * ANY WARRANTIES OR REPRESENTATIONS EXPRESS, IMPLIED OR STATUTORY; INCLUDING,
 * WITHOUT LIMITATION, WARRANTIES OF QUALITY, PERFORMANCE, NONINFRINGEMENT,
 * MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.  NOR ARE THERE ANY
 * WARRANTIES CREATED BY A COURSE OR DEALING, COURSE OF PERFORMANCE OR TRADE
 * USAGE.  FURTHERMORE, THERE ARE NO WARRANTIES THAT THE SOFTWARE WILL MEET
 * YOUR NEEDS OR BE FREE FROM ERRORS, OR THAT THE OPERATION OF THE SOFTWARE
 * WILL BE UNINTERRUPTED.  IN NO EVENT SHALL THE COPYRIGHT HOLDERS OR
 * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL,
 * EXEMPLARY, OR CONSEQUENTIAL DAMAGES HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * caching using a shared memory backend, FIFO-style
 * based on mod_auth_mellon code
 *
 * @Author: Hans Zandbelt - hans.zandbelt@gmail.com
 */

#include <unistd.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#ifdef AP_NEED_SET_MUTEX_PERMS
#include "unixd.h"
#endif

#include "../mod_oidc.h"

extern module AP_MODULE_DECLARE_DATA oidc_module;

/* size of key in cached key/value pairs */
#define OIDC_CACHE_SHM_KEY_MAX 128
/* max value size */
#define OIDC_CACHE_SHM_VALUE_MAX 16384

/* represents one (fixed size) cache entry, cq. name/value string pair */
typedef struct oidc_cache_shm_entry_t {
	/* name of the cache entry */
	char key[OIDC_CACHE_SHM_KEY_MAX];
	/* value of the cache entry */
	char value[OIDC_CACHE_SHM_VALUE_MAX];
	/* last (read) access timestamp */
	apr_time_t access;
	/* expiry timestamp */
	apr_time_t expires;
} oidc_cache_shm_entry_t;

/*
 * see if shared memory caching is used in any of the vhosts
 */
static apr_byte_t oidc_cache_shm_in_use(server_rec *s) {
	while (s != NULL) {
		oidc_cfg *c = ap_get_module_config(s->module_config, &oidc_module);
		if (c->cache == &oidc_cache_shm)
			return TRUE;
		s = s->next;
	}
	return FALSE;
}

/*
 * initialized the shared memory block in the parent process
 */
apr_byte_t oidc_cache_shm_init(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config,
			&oidc_module);

	if (oidc_cache_shm_in_use(s) == FALSE)
		return FALSE;

	// NB: this is global, vhosts inherit a pointer

	/* create the shared memory segment */
	apr_status_t rv = apr_shm_create(&cfg->cache_shm->shm,
			sizeof(oidc_cache_shm_entry_t) * cfg->cache_shm->cache_size_max,
			NULL, s->process->pool);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
				"oidc_cache_shm_init: apr_shm_create failed to create shared memory segment");
		return FALSE;
	}

	/* initialize the whole segment to '/0' */
	int i;
	oidc_cache_shm_entry_t *table = apr_shm_baseaddr_get(cfg->cache_shm->shm);
	for (i = 0; i < cfg->cache_shm->cache_size_max; i++) {
		table[i].key[0] = '\0';
		table[i].access = 0;
	}

	/* construct the mutex filename */
	cfg->cache_shm->mutex_filename = apr_psprintf(s->process->pool,
			"%s/httpd_mutex.%ld", cfg->cache_file_dir, (long int) getpid());

	/* create the mutex lock */
	rv = apr_global_mutex_create(&cfg->cache_shm->mutex,
			(const char *) cfg->cache_shm->mutex_filename, APR_LOCK_DEFAULT,
			s->process->pool);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
				"oidc_cache_shm_init: apr_global_mutex_create failed to create mutex on file %s",
				cfg->cache_shm->mutex_filename);
		return FALSE;
	}

	/* need this on Linux */
#ifdef AP_NEED_SET_MUTEX_PERMS
	rv = unixd_set_global_mutex_perms(cfg->cache_shm->mutex);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
				"oidc_cache_shm_init: unixd_set_global_mutex_perms failed; could not set permissions ");
		return FALSE;
	}
#endif

	return TRUE;
}

/*
 * initialize the shared memory segment in a child process
 */
void oic_cache_shm_child_init(apr_pool_t *p, server_rec *s) {
	oidc_cfg *cfg = ap_get_module_config(s->module_config, &oidc_module);

	/*
	 * see if any of the defined servers uses shm
	 * need to check this because this is registered as a generic child initialization
	 * routing, meaning it will be called for each type of cache
	 */
	if (oidc_cache_shm_in_use(s) == FALSE)
		return;

	/* initialize the lock for the child process */
	// TODO: should we use getppid to construct the mutex filename in the child and get rid of the cache_shm_mutex_filename in the config struct?
	apr_status_t rv = apr_global_mutex_child_init(&cfg->cache_shm->mutex,
			(const char *) cfg->cache_shm->mutex_filename, p);

	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, s,
				"oic_cache_shm_child_init: apr_global_mutex_child_init failed to reopen mutex on file %s",
				cfg->cache_shm->mutex_filename);
		exit(1);
	}
}

/*
 * get a value from the shared memory cache
 */
static apr_byte_t oidc_cache_shm_get(request_rec *r, const char *key,
		const char **value) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_cache_shm_get: entering \"%s\"", key);

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&oidc_module);

	apr_status_t rv;
	int i;

	/* grab the global lock */
	if ((rv = apr_global_mutex_lock(cfg->cache_shm->mutex)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
				"oidc_cache_shm_get: apr_global_mutex_lock() failed [%d]", rv);
		return FALSE;
	}

	/* get the pointer to the start of the shared memory block */
	oidc_cache_shm_entry_t *table = apr_shm_baseaddr_get(cfg->cache_shm->shm);

	/* loop over the block, looking for the key */
	for (i = 0; i < cfg->cache_shm->cache_size_max; i++) {
		const char *tablekey = table[i].key;

		if (tablekey == NULL)
			continue;

		if (strcmp(tablekey, key) == 0) {

			/* found a match, check if it has expired */
			if (table[i].expires > apr_time_now()) {

				/* update access timestamp */
				table[i].access = apr_time_now();
				*value = table[i].value;
			}
		}
	}

	/* release the global lock */
	apr_global_mutex_unlock(cfg->cache_shm->mutex);

	return TRUE;
}

/*
 * store a value in the shared memory cache
 */
static apr_byte_t oidc_cache_shm_set(request_rec *r, const char *key,
		const char *value, apr_time_t expiry) {

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&oidc_module);

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_cache_shm_set: entering \"%s\" (value size=(%ld)", key,
			strlen(value));

	oidc_cache_shm_entry_t *t;
	oidc_cache_shm_entry_t *table;
	apr_time_t current_time;
	int i;
	apr_time_t age;

	/* check that the passed in key is valid */
	if (key == NULL || strlen(key) > OIDC_CACHE_SHM_KEY_MAX) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_cache_shm_set: could not set value since key is NULL or too long (%s)",
				key);
		return FALSE;
	}

	/* check that the passed in value is valid */
	if (value == NULL || strlen(value) > OIDC_CACHE_SHM_VALUE_MAX) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_cache_shm_set: could not set value since value is NULL or too long (%ld > %d)",
				strlen(value), OIDC_CACHE_SHM_VALUE_MAX);
		return FALSE;
	}

	/* grab the global lock */
	if (apr_global_mutex_lock(cfg->cache_shm->mutex) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_cache_shm_set: apr_global_mutex_lock() failed");
		return FALSE;
	}

	/* get a pointer to the shared memory block */
	table = apr_shm_baseaddr_get(cfg->cache_shm->shm);

	/* get the current time */
	current_time = apr_time_now();

	/* loop over the slots in the shared memory block */
	t = &table[0];
	for (i = 0; i < cfg->cache_shm->cache_size_max; i++) {

		/* see if this is a free slot */
		if (table[i].key[0] == '\0') {
			t = &table[i];
			break;
		}

		/* see if this slot has expired */
		if (table[i].expires <= current_time) {
			t = &table[i];
			break;
		}

		/* see if this slot was less recently used than the current pointer */
		if (table[i].access < t->access) {
			t = &table[i];
		}
	}

	/* if we have no free slots, issue a warning about the LRU entry */
	if (t->key[0] != '\0' && t->expires > current_time) {
		age = (current_time - t->access) / 1000000;
		if (age < 3600) {
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r,
					"oidc_cache_shm_set: dropping LRU entry with age = %" APR_TIME_T_FMT "s, which is less than one hour; consider increasing the shared memory caching space (which is %d now) with the (global) OIDCCacheShmMax setting.",
					age, cfg->cache_shm->cache_size_max);
		}
	}

	/* fill out the entry with the provided data */
	strcpy(t->key, key);
	strcpy(t->value, value);
	t->expires = expiry;
	t->access = current_time;

	/* release the global lock */
	apr_global_mutex_unlock(cfg->cache_shm->mutex);

	return TRUE;
}

oidc_cache_t oidc_cache_shm = { oidc_cache_shm_get, oidc_cache_shm_set };
