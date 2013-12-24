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
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <apr_hash.h>
#include <apr_time.h>
#include <apr_strings.h>
#include <apr_pools.h>

#include <httpd.h>
#include <http_log.h>

#include "mod_oidc.h"

#define OIDC_CACHE_LINE_SIZE 2048

static const char *oidc_cache_path(request_rec *r) {
	const char *tmp_dir = NULL;
	apr_temp_dir_get(&tmp_dir, r->pool);
	char *path = apr_psprintf(r->pool, "%s/mod_oidc", tmp_dir);
	apr_dir_t *dir;
	if (apr_dir_open(&dir, path, r->pool) != APR_SUCCESS) {
		apr_dir_make_recursive(path, APR_OS_DEFAULT, r->pool);
	}
	return path;
}

static const char *oidc_cache_file(request_rec *r, const char *key) {
	return apr_psprintf(r->pool, "%s/%s", oidc_cache_path(r), key);
}

apr_status_t oidc_cache_get_expiry(request_rec *r, const char *path, apr_file_t *f, apr_time_t *expiry) {
	apr_status_t rc = APR_SUCCESS;
	char line[OIDC_CACHE_LINE_SIZE];
	if ((rc = apr_file_gets(line, sizeof(line), f)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_get: could not read first line (expiry) from %s", path);
	} else if (sscanf(line, "%" APR_TIME_T_FMT, expiry) != 1) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_get: could not scan first line (expiry) from %s", path);
		rc = APR_EGENERAL;
	}
	return rc;
}

apr_status_t oidc_cache_get(request_rec *r, const char *key, const char **value) {
	apr_file_t *f;
	apr_status_t rc = APR_SUCCESS;

	const char *path = oidc_cache_file(r, key);

	if (apr_file_open(&f, path, APR_FOPEN_READ|APR_FOPEN_BUFFERED, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_cache_get: cache miss '%s'", key);
		return APR_SUCCESS;
	}

	apr_file_lock(f, APR_FLOCK_EXCLUSIVE);
	apr_off_t begin = 0;
	apr_file_seek(f, APR_SET, &begin);

	apr_time_t expiry;
	if ((rc = oidc_cache_get_expiry(r, path, f, &expiry)) != APR_SUCCESS) goto error_close;

	char line[OIDC_CACHE_LINE_SIZE];
	apr_array_header_t *arr = apr_array_make(r->pool, 10, sizeof(char *));
	while (!apr_file_eof(f) ) {
		rc = apr_file_gets(line, sizeof(line), f);
		if (rc == APR_EOF) break;
		if (rc != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_get: could not read cache entry line from %s", path);
			goto error_close;
		}
		*((const char **) apr_array_push(arr)) = apr_pstrdup(r->pool, line);
	}

	apr_file_unlock(f);
	apr_file_close(f);

	if (apr_time_now() >= expiry) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_cache_get: cache entry (%s) expired, removing file (%s)", key, path);
		if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_get: could not delete cache file %s", path);
			goto error_end;
		}
	} else {
		*value = apr_array_pstrcat(r->pool, arr, 0);
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_cache_get: got entry (expires in: %ld) %s=%s", apr_time_sec(expiry - apr_time_now()), key, *value);
	}

	return APR_SUCCESS;

error_close:
	apr_file_unlock(f);
	apr_file_close(f);

error_end:
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_get: return error status (%d)", rc);

	return rc;
}

#define OIDC_CACHE_CLEAN_ONLY_ONCE_PER_N_SECS 60
#define OIDC_CACHE_FILE_LAST_CLEANED "mod-oidc-last-cleaned"

apr_status_t oidc_cache_clean(request_rec *r) {
	apr_status_t rc = APR_SUCCESS;
	apr_dir_t *dir;
	apr_file_t *file;
	apr_status_t i;
	apr_finfo_t fi;
	const char *path, *cache_dir = oidc_cache_path(r);

	// really clean only once per minute
	path = apr_psprintf(r->pool, "%s/%s", cache_dir, OIDC_CACHE_FILE_LAST_CLEANED);
	if ((rc = apr_stat(&fi, path, APR_FINFO_MTIME, r->pool))  == APR_SUCCESS)  {
		if (apr_time_now() < fi.mtime + apr_time_from_sec(OIDC_CACHE_CLEAN_ONLY_ONCE_PER_N_SECS)) {
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_cache_clean: last cleanup call was less than a minute ago (next one as early as in %ld secs)", apr_time_sec(fi.mtime + apr_time_from_sec(OIDC_CACHE_CLEAN_ONLY_ONCE_PER_N_SECS) - apr_time_now()));
			return APR_SUCCESS;
		}
		apr_file_mtime_set(path, apr_time_now(), r->pool);
	} else {
		if (apr_file_open(&file, path, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_clean: error creating cache timestamp %s", path);
		}
	}

	if ((rc = apr_dir_open(&dir, cache_dir, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_clean: error opening cache directory '%s' for cleaning", cache_dir);
		return rc;
	}

	do {
		i = apr_dir_read(&fi, APR_FINFO_NAME, dir);
		if (i == APR_SUCCESS) {
			if (fi.name[0] == '.') continue;
			if (apr_strnatcmp(fi.name, OIDC_CACHE_FILE_LAST_CLEANED) == 0) continue;

			path = oidc_cache_file(r, fi.name);

			if (apr_file_open(&file, path, APR_FOPEN_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_cache_clean: unable to open cache entry '%s'", path);
				continue;
			}

			apr_time_t expiry;
			oidc_cache_get_expiry(r, path, file, &expiry);
			apr_file_close(file);

			if (rc == APR_SUCCESS) {
				if (apr_time_now() < expiry) continue;
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_cache_clean: cache entry (%s) expired, removing file (%s)", fi.name, path);
			} else {
				ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_cache_clean: cache entry (%s) corrupted, removing file (%s)", fi.name, path);
			}

			if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_clean: could not delete cache file %s", path);
			}
		}
	} while (i == APR_SUCCESS);

	apr_dir_close(dir);

	return APR_SUCCESS;
}

apr_status_t oidc_cache_set(request_rec *r, const char *key, const char *value, apr_time_t expiry) {
	const char *path = oidc_cache_file(r, key);

	oidc_cache_clean(r);

	apr_file_t *f;
	if (apr_file_open(&f, path, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_cache_set: cache entry '%s' could not be opened", path);
		return APR_EGENERAL;
	}
	apr_file_lock(f, APR_FLOCK_EXCLUSIVE);
	apr_off_t begin = 0;
	apr_file_seek(f, APR_SET, &begin);

	apr_file_printf(f, "%" APR_TIME_T_FMT "\n", expiry);
	apr_file_printf(f, "%s",value);

	apr_file_unlock(f);
	apr_file_close(f);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_cache_set: set entry (expires in: %ld) %s=%s", apr_time_sec(expiry - apr_time_now()), key, value);

	return APR_SUCCESS;
}
