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
 * Copyright (C) 2013 Ping Identity Corporation
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

#include <apr_base64.h>
#include <apr_lib.h>

#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <http_log.h>

#include "mod_oidc.h"

extern module AP_MODULE_DECLARE_DATA oidc_module;

session_rec * oidc_session_empty(apr_pool_t *pool) {
	session_rec *zz = apr_pcalloc(pool, sizeof(session_rec));
	zz->pool = pool;
	zz->uuid = (apr_uuid_t *) apr_pcalloc(zz->pool, sizeof(apr_uuid_t));
	apr_uuid_get(zz->uuid);
	zz->remote_user = NULL;
	zz->encoded = NULL;
	zz->entries = apr_table_make(zz->pool, 10);
	return zz;
}

#define OIDC_SESSION_REMOTE_USER_KEY "remote-user"
#define OIDC_SESSION_EXPIRY_KEY      "oidc-expiry"

apr_status_t oidc_session_load_cookie(request_rec *r, session_rec *z) {
	oidc_dir_cfg *d = ap_get_module_config(r->per_dir_config, &oidc_module);
	char *value = oidc_get_cookie(r, d->cookie);
	if (value != NULL) {
		if (oidc_base64url_decode_decrypt_string(r, (char **)&z->encoded, value) <= 0) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_is_valid_cookie: could not decrypt cookie value");
			return APR_EGENERAL;
		}
	}
	return APR_SUCCESS;
}

apr_status_t oidc_session_save_cookie(request_rec *r, session_rec *z) {
	oidc_dir_cfg *d = ap_get_module_config(r->per_dir_config, &oidc_module);
	char *crypted = NULL;
	oidc_encrypt_base64url_encode_string(r, &crypted, z->encoded);
	oidc_set_cookie(r, d->cookie, crypted);
	return APR_SUCCESS;
}

#include "oidc_compat.c"

// copied from mod_session.c
static apr_status_t oidc_session_identity_decode(request_rec * r, session_rec * z) {
	   char *last = NULL;
	    char *encoded, *pair;
	    const char *sep = "&";

		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_session_identity_decode: decoding %s", z->encoded);

	    /* sanity check - anything to decode? */
	    if (!z->encoded) {
	        return APR_SUCCESS;
	    }

	    /* decode what we have */
	    encoded = apr_pstrdup(r->pool, z->encoded);
	    pair = apr_strtok(encoded, sep, &last);
	    while (pair && pair[0]) {
	        char *plast = NULL;
	        const char *psep = "=";
	        char *key = apr_strtok(pair, psep, &plast);
	        char *val = apr_strtok(NULL, psep, &plast);

			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_session_identity_decode: decoding %s=%s", key, val);

	        if (key && *key) {
	            if (!val || !*val) {
	                apr_table_unset(z->entries, key);
	            }
	            else if (!ap_unescape_urlencoded(key) && !ap_unescape_urlencoded(val)) {
	                if (!strcmp(OIDC_SESSION_EXPIRY_KEY, key)) {
	                    z->expiry = (apr_time_t) apr_atoi64(val);
	                }
	                else {
	                    apr_table_set(z->entries, key, val);
	                }
	            }
	        }
	        pair = apr_strtok(NULL, sep, &last);
	    }
	    z->encoded = NULL;
	    return APR_SUCCESS;
}

// copied from mod_session.c
static int oidc_identity_count(int *count, const char *key, const char *val) {
    *count += strlen(key) * 3 + strlen(val) * 3 + 1;
    return 1;
}

// copied from mod_session.c
static int oidc_identity_concat(char *buffer, const char *key, const char *val) {
    char *slider = buffer;
    int length = strlen(slider);
    slider += length;
    if (length) {
        *slider = '&';
        slider++;
    }
    ap_escape_urlencoded_buffer(slider, key);
    slider += strlen(slider);
    *slider = '=';
    slider++;
    ap_escape_urlencoded_buffer(slider, val);
    return 1;
}

// copied from mod_session.c
static apr_status_t oidc_session_identity_encode(request_rec * r, session_rec * z) {
    char *buffer = NULL;
    int length = 0;
    if (z->expiry) {
        char *expiry = apr_psprintf(z->pool, "%" APR_INT64_T_FMT, z->expiry);
        apr_table_setn(z->entries, OIDC_SESSION_EXPIRY_KEY, expiry);
    }
    apr_table_do((int (*) (void *, const char *, const char *))
    		oidc_identity_count, &length, z->entries, NULL);
    buffer = apr_pcalloc(r->pool, length + 1);
    apr_table_do((int (*) (void *, const char *, const char *))
    		oidc_identity_concat, buffer, z->entries, NULL);
    z->encoded = buffer;
    return APR_SUCCESS;

}

apr_status_t oidc_session_load_pool(request_rec *r, session_rec *z) {
	oidc_dir_cfg *d = ap_get_module_config(r->per_dir_config, &oidc_module);

	char *uuid = oidc_get_cookie(r, d->cookie);
	if (uuid != NULL) oidc_cache_get(r, uuid, &z->encoded);

	return APR_SUCCESS;
}

apr_status_t oidc_session_save_pool(request_rec *r, session_rec *z) {
	oidc_dir_cfg *d = ap_get_module_config(r->per_dir_config, &oidc_module);

	char key[APR_UUID_FORMATTED_LENGTH + 1];
	apr_uuid_format((char *)&key, z->uuid);
	oidc_set_cookie(r, d->cookie, key);

	oidc_cache_set(r, key, z->encoded, z->expiry);

	return APR_SUCCESS;
}

apr_status_t oidc_session_load(request_rec *r, session_rec **z) {
#ifdef OIDC_SESSION_USE_APACHE_SESSIONS
#else
	*z = oidc_session_empty(r->server->process->pool);
	session_rec *zz = *z;

	//apr_status_t rc = oidc_session_load_cookie(r, zz);
	apr_status_t rc = oidc_session_load_pool(r, zz);
	if (rc == APR_SUCCESS) {
		rc = oidc_session_identity_decode(r, zz);
	}
	zz->remote_user = apr_table_get(zz->entries, OIDC_SESSION_REMOTE_USER_KEY);
	return rc;
#endif
}

apr_status_t oidc_session_save(request_rec *r, session_rec *z) {
#ifdef OIDC_SESSION_USE_APACHE_SESSIONS
#else
	// temporary? workaround for remote_user pool (set in main module...)
	apr_table_set(z->entries, OIDC_SESSION_REMOTE_USER_KEY, z->remote_user);
	oidc_session_identity_encode(r, z);
	//return oidc_session_save_cookie(r, z);
	return oidc_session_save_pool(r, z);
#endif
}

apr_status_t oidc_session_get(request_rec *r, session_rec *z, const char *key, const char **value) {
#ifdef OIDC_SESSION_USE_APACHE_SESSIONS
#else
	*value = apr_table_get(z->entries, key);
	return OK;
#endif
}

apr_status_t oidc_session_set(request_rec *r, session_rec *z, const char *key, const char *value) {
#ifdef OIDC_SESSION_USE_APACHE_SESSIONS
#else
	if (value) {
		apr_table_set(z->entries, key, value);
	} else {
		apr_table_unset(z->entries, key);
	}
	return OK;
#endif
}
