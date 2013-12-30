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

/*
 * mem_cache-like interface and semantics (string keys/values) using a file storage backend
 * TODO: make the cache path configurable so it can be shared across different machines using a shared file system
 */

#include <apr_hash.h>
#include <apr_time.h>
#include <apr_strings.h>
#include <apr_pools.h>

#include <httpd.h>
#include <http_log.h>

#include "mod_oidc.h"

/*
 * header structure that holds the metadata info for a cache file entry
 */
typedef struct {
	/* length of the cached data */
	apr_size_t len;
	/* cache expiry timestamp */
    apr_time_t expire;
} oidc_cache_info_t;

/*
 * return the path to the directory where the cache files reside
 */
static const char *oidc_cache_dir_path(request_rec *r) {

	char *path = NULL;
	const char *tmp_dir = NULL;
	apr_dir_t *dir;

	/* get an OS specific temporary directory */
	apr_temp_dir_get(&tmp_dir, r->pool);

	/* append the mod_oidc specific path portion */
	path = apr_psprintf(r->pool, "%s/mod_oidc", tmp_dir);

	/* ensure the directory exists */
	if (apr_dir_open(&dir, path, r->pool) != APR_SUCCESS) {
		apr_dir_make_recursive(path, APR_OS_DEFAULT, r->pool);
	}

	return path;
}

/*
 * return the fully qualified path name to a cache file for a specified key
 */
static const char *oidc_cache_file(request_rec *r, const char *key) {
	return apr_psprintf(r->pool, "%s/%s", oidc_cache_dir_path(r), key);
}

/*
 * read a specified number of bytes from a cache file in to a preallocated buffer
 */
static apr_status_t oidc_cache_file_read(request_rec *r, const char *path, apr_file_t *fd, void *buf, const apr_size_t len) {

	apr_status_t rc = APR_SUCCESS;
	apr_size_t bytes_read = 0;

	/* (blocking) read the requested number of bytes */
	rc = apr_file_read_full(fd, buf, len, &bytes_read);

	/* test for system errors */
	if (rc != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_file_read: could not read from: %s", path);
	}

	/* ensure that we've got the requested number of bytes */
	if (bytes_read != len) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_file_read: could not read enough bytes from: \"%s\", bytes_read (%ld) != len (%ld)", path, bytes_read, len);
		rc = APR_EGENERAL;
	}

	return rc;
}

/*
 * write a specified number of bytes from a buffer to a cache file
 */
static apr_status_t oidc_cache_file_write(request_rec *r, const char *path, apr_file_t *fd, void *buf, const apr_size_t len) {

	apr_status_t rc = APR_SUCCESS;
	apr_size_t bytes_written = 0;

	/* (blocking) write the number of bytes in the buffer */
	rc = apr_file_write_full(fd, buf, len, &bytes_written);

	/* check for a system error */
	if (rc != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_file_write: could not write to: \"%s\"", path);
		return rc;
	}

	/* check that all bytes from the header were written */
	if (bytes_written !=  len) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_file_write: could not write enough bytes to: \"%s\", bytes_written (%ld) != len (%ld)", path, bytes_written, len);
		return APR_EGENERAL;
	}

	return rc;
}

/*
 * get a value for the specified key from the cache
 */
apr_status_t oidc_cache_get(request_rec *r, const char *key, const char **value) {
	apr_file_t *fd;
	apr_status_t rc = APR_SUCCESS;

	/* get the fully qualified path to the cache file based on the key name */
	const char *path = oidc_cache_file(r, key);

	/* open the cache file if it exists, otherwise we just have a "regular" cache miss */
	if (apr_file_open(&fd, path, APR_FOPEN_READ|APR_FOPEN_BUFFERED, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_cache_get: cache miss for key \"%s\"", key);
		return APR_SUCCESS;
	}

	/* the file exists, now lock it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);

	/* move the read pointer to the very start of the cache file */
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* read a header with metadata */
	oidc_cache_info_t info;
	if ((rc = oidc_cache_file_read(r, path, fd, &info, sizeof(oidc_cache_info_t))) != APR_SUCCESS)
		goto error_close;

	/* check if this cache entry has already expired */
	if (apr_time_now() >= info.expire) {

		/* yep, expired: unlock and close before deleting the cache file */
		apr_file_unlock(fd);
		apr_file_close(fd);

		/* log this event */
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_cache_get: cache entry (%s) expired, removing file (%s)", key, path);

		/* and kill it */
		if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_get: could not delete cache file %s", path);
		}

		/* nothing strange happened really */
		return APR_SUCCESS;
	}

	/* allocate space for the actual value based on the data size info in the header (+1 for \0 termination) */
	*value = apr_palloc(r->pool, info.len + 1);

	/* (blocking) read the requested data in to the buffer */
	rc = oidc_cache_file_read(r, path, fd, (void *)*value, info.len);

	/* barf on failure */
	if (rc != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_get: could not read cache value from %s", path);
		goto error_close;
	}

	/* \0 terminate the string that we've just read */
	value[info.len] = '\0';

	/* we're done, unlock and close the file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	/* log a succesful cache hit */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_cache_get: cache hit for key \"%s\" (%ld bytes, expiring in: %ld)", key, info.len, apr_time_sec(info.expire - apr_time_now()));

	return APR_SUCCESS;

error_close:
	apr_file_unlock(fd);
	apr_file_close(fd);

	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_get: return error status (%d)", rc);

	return rc;
}

#define OIDC_CACHE_CLEAN_ONLY_ONCE_PER_N_SECS 60
#define OIDC_CACHE_FILE_LAST_CLEANED "mod-oidc-last-cleaned"

/*
 * delete all expired entries from the cache directory
 */
apr_status_t oidc_cache_clean(request_rec *r) {
	apr_status_t rc = APR_SUCCESS;
	apr_dir_t *dir;
	apr_file_t *fd;
	apr_status_t i;
	apr_finfo_t fi;
	oidc_cache_info_t info;

	/* get the path to the cache directory */
	const char *cache_dir = oidc_cache_dir_path(r);

	/* get the path to the metadata file that holds "last cleaned" metadata info */
	const char *path = apr_psprintf(r->pool, "%s/%s", cache_dir, OIDC_CACHE_FILE_LAST_CLEANED);

	/* open the metadata file if it exists */
	if ((rc = apr_stat(&fi, path, APR_FINFO_MTIME, r->pool))  == APR_SUCCESS)  {

		/* really only clean once per so much time, check that we haven not recently run */
		if (apr_time_now() < fi.mtime + apr_time_from_sec(OIDC_CACHE_CLEAN_ONLY_ONCE_PER_N_SECS)) {
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_cache_clean: last cleanup call was less than a minute ago (next one as early as in %ld secs)", apr_time_sec(fi.mtime + apr_time_from_sec(OIDC_CACHE_CLEAN_ONLY_ONCE_PER_N_SECS) - apr_time_now()));
			return APR_SUCCESS;
		}

		/* time to clean, reset the modification time of the metadata file to reflect the timestamp of this cleaning cycle */
		apr_file_mtime_set(path, apr_time_now(), r->pool);

	} else {

		/* no metadata file exists yet, create one and open it */
		if ((rc = apr_file_open(&fd, path, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_clean: error creating cache timestamp %s", path);
			return rc;
		}
	}

	/* time to clean, open the cache directory */
	if ((rc = apr_dir_open(&dir, cache_dir, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_clean: error opening cache directory '%s' for cleaning", cache_dir);
		return rc;
	}

	/* loop trough the cache file entries */
	do {

		/* read the next entry from the directory */
		i = apr_dir_read(&fi, APR_FINFO_NAME, dir);

		if (i == APR_SUCCESS) {

			/* skip non-cache entries, cq. the ".", ".." and the metadata file */
			if ( (fi.name[0] == '.') || (apr_strnatcmp(fi.name, OIDC_CACHE_FILE_LAST_CLEANED) == 0) ) continue;

			/* get the fully qualified path to the cache file and open it */
			path = oidc_cache_file(r, fi.name);
			if (apr_file_open(&fd, path, APR_FOPEN_READ, APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_clean: unable to open cache entry '%s'", path);
				continue;
			}

			/* read the header with cache metadata info and close the file */
			rc = oidc_cache_file_read(r, path, fd, &info, sizeof(oidc_cache_info_t));
			apr_file_close(fd);

			if (rc == APR_SUCCESS) {

				/* check if this entry expired, if not just continue to the next entry */
				if (apr_time_now() < info.expire) continue;

				/* the cache entry expired, we're going to remove it so log that event */
				ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_cache_clean: cache entry (%s) expired, removing file (%s)", fi.name, path);

			} else {

				/* file open returned an error, log that */
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_clean: cache entry (%s) corrupted, removing file (%s)", fi.name, path);

			}

			/* delete the cache file */
			if ((rc = apr_file_remove(path, r->pool)) != APR_SUCCESS) {

				/* hrm, this will most probably happen again on the next run... */
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_clean: could not delete cache file: %s", path);
			}

		}

	} while (i == APR_SUCCESS);

	apr_dir_close(dir);

	return APR_SUCCESS;
}

/*
 * write a value for the specified key to the cache
 */
apr_status_t oidc_cache_set(request_rec *r, const char *key, const char *value, apr_time_t expiry) {
	apr_file_t *fd;
	apr_status_t rc = APR_SUCCESS;

	/* get the fully qualified path to the cache file based on the key name */
	const char *path = oidc_cache_file(r, key);

	/* only on writes (not on reads) we clean the cache first (if not done recently) */
	oidc_cache_clean(r);

	/* try to open the cache file for writing, creating it if it does not exist */
	if (apr_file_open(&fd, path, (APR_FOPEN_WRITE|APR_FOPEN_CREATE), APR_OS_DEFAULT, r->pool) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_cache_set: cache file \"%s\" could not be opened", path);
		return APR_EGENERAL;
	}

	/* lock the file and move the write pointer to the start of it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* construct the metadata for this cache entry in the header info */
	oidc_cache_info_t info;
	info.expire = expiry;
	info.len = strlen(value);

	/* write the header */
	if ((rc = oidc_cache_file_write(r, path, fd, &info, sizeof(oidc_cache_info_t))) != APR_SUCCESS)
		return rc;

	/* next write the value */
	if ((rc = oidc_cache_file_write(r, path, fd, (void *)value, info.len)) != APR_SUCCESS)
		return rc;

	/* unlock and close the written file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	/* log our success */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_cache_set: set entry for key \"%s\" (expires in: %ld)", key, apr_time_sec(expiry - apr_time_now()));

	return APR_SUCCESS;
}
