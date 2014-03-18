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
 * caching using a memcache backend
 *
 * @Author: Hans Zandbelt - hans.zandbelt@gmail.com
 */

#include "apr_general.h"
#include "apr_strings.h"
#include "apr_hash.h"
#include "apr_memcache.h"

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>

#include "../mod_oidc.h"

// TODO: proper memcache error reporting (server unreachable etc.)

extern module AP_MODULE_DECLARE_DATA oidc_module;

/*
 * initialize the memcache struct to a number of memcache servers
 */
const char * oidc_cache_memcache_init(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);

	apr_status_t rv = APR_SUCCESS;
	int nservers = 0;
	char* split;
	char* tok;
	apr_pool_t *p = cmd->server->process->pool;

	/* loop over the provided memcache servers to find out the number of servers configured */
	char *cache_config = apr_pstrdup(p, arg);
	split = apr_strtok(cache_config, " ", &tok);
	while (split) {
		nservers++;
		split = apr_strtok(NULL, " ", &tok);
	}

	/* allocated space for the number of servers */
	rv = apr_memcache_create(p, nservers, 0, &cfg->cache_memcache);
	if (rv != APR_SUCCESS) {
		ap_log_error(APLOG_MARK, APLOG_ERR, rv, cmd->server,
				"oidc_cache_memcache_init: failed to create memcache object of '%d' size",
				nservers);
		return "error";
	}

	/* loop again over the provided servers */
	cache_config = apr_pstrdup(p, arg);
	split = apr_strtok(cache_config, " ", &tok);
	while (split) {
		apr_memcache_server_t* st;
		char* host_str;
		char* scope_id;
		apr_port_t port;

		/* parse out host and port */
		rv = apr_parse_addr_port(&host_str, &scope_id, &port, split, p);
		if (rv != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, rv, cmd->server,
					"oidc_cache_memcache_init: failed to parse cache server: '%s'",
					split);
			return "error";
		}

		if (host_str == NULL) {
			ap_log_error(APLOG_MARK, APLOG_ERR, rv, cmd->server,
					"oidc_cache_memcache_init: failed to parse cache server, "
							"no hostname specified: '%s'", split);
			return "error";
		}

		if (port == 0)
			port = 11211;

		/* create the memcache server struct */
		// TODO: tune this
		rv = apr_memcache_server_create(p, host_str, port, 0, 1, 1, 60, &st);
		if (rv != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, rv, cmd->server,
					"oidc_cache_memcache_init: failed to create cache server: %s:%d",
					host_str, port);
			return "error";
		}

		/* add the memcache server struct to the list */
		rv = apr_memcache_add_server(cfg->cache_memcache, st);
		if (rv != APR_SUCCESS) {
			ap_log_error(APLOG_MARK, APLOG_ERR, rv, cmd->server,
					"oidc_cache_memcache_init: failed to add cache server: %s:%d",
					host_str, port);
			return "error";
		}

		/* go to the next entry */
		split = apr_strtok(NULL, " ", &tok);
	}

	return NULL;
}

/*
 * get a name/value pair from memcache
 */
static apr_byte_t oidc_cache_memcache_get(request_rec *r, const char *key,
		const char **value) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_cache_memcache_get: entering \"%s\"", key);

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&oidc_module);
	apr_size_t len = 0;

	/* get it */
	apr_status_t rv = apr_memcache_getp(cfg->cache_memcache, r->pool, key,
			(char **)value, &len, NULL);

	// TODO: error strings ?
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
				"oidc_cache_memcache_get: apr_memcache_getp returned an error");
		return FALSE;
	}

	/* do sanity checking on the string value */
	if ( (*value) && (strlen(*value) != len) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
				"oidc_cache_memcache_get: apr_memcache_getp returned less bytes than expected: strlen(value) [%ld] != len [%ld]", strlen(*value), len);
		return FALSE;
	}

	return TRUE;
}

/*
 * store a name/value pair in memcache
 */
static apr_byte_t oidc_cache_memcache_set(request_rec *r, const char *key,
		const char *value, apr_time_t expiry) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_cache_memcache_set: entering \"%s\"", key);

	oidc_cfg *cfg = ap_get_module_config(r->server->module_config,
			&oidc_module);

	/* calculate the timeout from now */
	apr_uint32_t timeout = apr_time_sec(expiry - apr_time_now());

	/* store it */
	apr_status_t rv = apr_memcache_set(cfg->cache_memcache, key, (char *)value,
			strlen(value), timeout, 0);

	// TODO: error strings ?
	if (rv != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, rv, r,
				"oidc_cache_memcache_set: apr_memcache_set returned an error");
	}

	return (rv == APR_SUCCESS);
}

oidc_cache_t oidc_cache_memcache = { oidc_cache_memcache_get, oidc_cache_memcache_set };
