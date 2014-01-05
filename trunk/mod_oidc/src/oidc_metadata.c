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
 * OpenID Connect metadata handling routines, for both OP discovery and client registration
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

extern module AP_MODULE_DECLARE_DATA oidc_module;

#define OIDC_METADATA_SUFFIX_PROVIDER "provider"
#define OIDC_METADATA_SUFFIX_CLIENT "client"

/*
 * get the metadata filename for a specified issuer (cq. urlencode it)
 */
static const char *oidc_metadata_issuer_to_filename(request_rec *r, const char *issuer) {
	return oidc_escape_string(r, issuer);
}

/*
 * get the issuer from a metadata filename (cq. urldeccode it)
 */
static const char *oidc_metadata_filename_to_issuer(request_rec *r, const char *filename) {
	char *result = apr_pstrdup(r->pool, filename);
	char *p = strrchr(result, '.');
	*p = '\0';
	ap_unescape_url(result);
	return result;
}

/*
 * get the full path to the metadata file for a specified issuer and directory
 */
static const char *oidc_metadata_file_path(request_rec *r, oidc_cfg *cfg, const char *issuer, const char *type) {
	return apr_psprintf(r->pool, "%s/%s.%s", cfg->metadata_dir, oidc_metadata_issuer_to_filename(r, issuer), type);
}

/*
 * get the full path to the provider metadata file for a specified issuer
 */
static const char *oidc_metadata_provider_file_path(request_rec *r, const char *issuer) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &oidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_PROVIDER);
}

/*
 * get the full path to the client metadata file for a specified issuer
 */
static const char *oidc_metadata_client_file_path(request_rec *r, const char *issuer) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &oidc_module);
	return oidc_metadata_file_path(r, cfg, issuer, OIDC_METADATA_SUFFIX_CLIENT);
}

static apr_status_t oidc_metadata_file_read_json(request_rec *r, const char *path, apr_json_value_t **result) {
	apr_file_t *fd;
	apr_status_t rc = APR_SUCCESS;
	char s_err[128];
	apr_finfo_t finfo;

	/* open the JSON file if it exists */
	if ((rc = apr_file_open(&fd, path, APR_FOPEN_READ|APR_FOPEN_BUFFERED, APR_OS_DEFAULT, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_file_read_json: no JSON file found at: \"%s\"", path);
		return rc;
	}

	/* the file exists, now lock it */
	apr_file_lock(fd, APR_FLOCK_EXCLUSIVE);

	/* move the read pointer to the very start of the cache file */
	apr_off_t begin = 0;
	apr_file_seek(fd, APR_SET, &begin);

	/* get the file info so we know its size */
	if ((rc = apr_file_info_get(&finfo, APR_FINFO_SIZE, fd)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_file_read_json: error calling apr_file_info_get on JSON file: \"%s\"", path);
		goto error_close;
	}

	/* now that we have the size of the file, allocate a buffer that can contain its contents */
	char *buf = apr_palloc(r->pool, finfo.size + 1);

	/* read the file in to the buffer */
	apr_size_t bytes_read = 0;
	if ((rc = apr_file_read_full(fd, buf, finfo.size, &bytes_read)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_file_read_json: apr_file_read_full on (%s) returned an error: %s", path, apr_strerror(rc, s_err, sizeof(s_err)));
		goto error_close;
	}

	/* check that we've got all of it */
	if (bytes_read != finfo.size) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_file_read_json: apr_file_read_full on (%s) returned less bytes (%ld) than expected: (%lld)", path, bytes_read, finfo.size);
		goto error_close;
	}

	/* we're done, unlock and close the file */
	apr_file_unlock(fd);
	apr_file_close(fd);

	/* just to be sure, we set a \0 (we allocated space for it anyway) */
	buf[bytes_read] = '\0';

	/* decode the JSON contents of the buffer */
	if ((rc = apr_json_decode(result, buf, strlen(buf), r->pool)) != APR_SUCCESS) {
		/* something went wrong */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_file_read_json: JSON parsing (%s) returned an error: (%d)", path, rc);
	} else if ( (*result == NULL) || ((*result)->type != APR_JSON_OBJECT) ) {
		/* oops, no JSON */
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_file_read_json: parsed JSON from (%s) did not contain a JSON object", path);
		rc = APR_EGENERAL;
	} else {
		/* log succesful metadata retrieval */
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_metadata_file_read_json: JSON parsed from file \"%s\"", path);
	}

	return rc;

error_close:
	apr_file_unlock(fd);
	apr_file_close(fd);

	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_file_read_json: return error status (%d) (%s)", rc,  apr_strerror(rc, s_err, sizeof(s_err)));

	return rc;
}

/*
 * get a list of configured OIDC providers based on the entries in the provider metadata directory
 */
apr_status_t oidc_metadata_list(request_rec *r, oidc_cfg *cfg, apr_array_header_t **list) {
	apr_status_t rc = APR_SUCCESS;
	apr_dir_t *dir;
	apr_finfo_t fi;
	apr_status_t i;
	char s_err[128];

	/* open the metadata directory */
	if ((rc = apr_dir_open(&dir, cfg->metadata_dir, r->pool)) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_list: error opening metadata directory '%s' (%s)", cfg->metadata_dir,  apr_strerror(rc, s_err, sizeof(s_err)));
		return rc;
	}

	// TODO: can estimate number in array based on # directory entries
	/* allocate space in the array that will hold the list of providers */
	*list = apr_array_make(r->pool, 5, sizeof(sizeof(const char*)));

	/* loop over the entries in the provider metadata directory */
	while (apr_dir_read(&fi, APR_FINFO_NAME, dir) == APR_SUCCESS) {

		/* skip "." and ".." entries */
		if (fi.name[0] == '.') continue;
		/* skip other non-provider entries */
		char *ext = strrchr(fi.name, '.');
		if ( (ext == NULL) || (strcmp(++ext, OIDC_METADATA_SUFFIX_PROVIDER) != 0) ) continue;

		/* push the decoded issuer filename in to the array */
		*(const char**)apr_array_push(*list) = oidc_metadata_filename_to_issuer(r, fi.name);
	}

	/* we're done, cleanup now */
	apr_dir_close(dir);

	return APR_SUCCESS;
}

/*
 * get the metadata for a specified issuer
 *
 * this fill the oidc_op_meta_t struct based on the issuer filename by reading and merging
 * contents from both provider metadata directory and client metadata directory
 */
apr_status_t oidc_metadata_get(request_rec *r, oidc_cfg *cfg, const char *issuer, oidc_provider_t **result) {

	apr_status_t rc = APR_SUCCESS;

	/* pointer to the parsed JSON metadata from the provider directory */
	apr_json_value_t *j_provider = NULL;
	/* pointer to the parsed JSON metadata from the client directory */
	apr_json_value_t *j_client = NULL;

	/* get the full file path to the provider metadata for this issuer */
	const char *provider_path = oidc_metadata_provider_file_path(r, issuer);
	/* and read the provider metadata in to the "provider" variable */
	if ((rc = oidc_metadata_file_read_json(r, provider_path, &j_provider)) != APR_SUCCESS) return rc;

	/* get the full file path to the client metadata for this issuer */
	const char *client_path = oidc_metadata_client_file_path(r, issuer);
	/* and read the client metadata in to the "client" variable */
	if ((rc = oidc_metadata_file_read_json(r, client_path, &j_client)) != APR_SUCCESS) return rc;

	/* allocate space for a parsed-and-merged metadata struct */
	*result = apr_pcalloc(r->pool, sizeof(oidc_provider_t));
	/* provide easy pointer */
	oidc_provider_t *provider = *result;

	// PROVIDER

	/* get the "issuer" from the provider metadata and double-check that it matches what we looked for */
	apr_json_value_t *j_issuer = apr_hash_get(j_provider->value.object, "issuer", APR_HASH_KEY_STRING);
	if ( (j_issuer == NULL) || (j_issuer->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: provider JSON object did not contain an \"issuer\" string");
		return FALSE;
	}
	if (strcmp(issuer, j_issuer->value.string.p) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: requested issuer (%s) does not match the \"issuer\" value in the metadata file (%s): %s", issuer, provider_path, j_issuer->value.string.p);
		return FALSE;
	}

	/* verify that the provider supports the "code" flow, cq. the only one that we support for now */
	apr_json_value_t *j_response_types_supported = apr_hash_get(j_provider->value.object, "response_types_supported", APR_HASH_KEY_STRING);
	if ( (j_response_types_supported == NULL) || (j_response_types_supported->type != APR_JSON_ARRAY) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: provider JSON object did not contain a \"response_types_supported\" array; assuming that \"code\" flow is supported...");
		// TODO: hey, this is required-by-spec stuff right?
	} else {
		int i;
		for (i = 0; i < j_response_types_supported->value.array->nelts; i++) {
			apr_json_value_t *elem = APR_ARRAY_IDX(j_response_types_supported->value.array, i, apr_json_value_t *);
			if (elem->type != APR_JSON_STRING) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: unhandled in-array JSON object type [%d] in provider metadata for entry \"response_types_supported\"", elem->type);
				continue;
			}
			if (strcmp(elem->value.string.p, "code") == 0) {
				break;
			}
		}
		if (i == j_response_types_supported->value.array->nelts) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: could not find a supported value [\"code\"] in provider metadata for entry \"response_types_supported\"");
			return FALSE;
		}
	}

	/* get a handle to the authorization endpoint */
	apr_json_value_t *j_authorization_endpoint = apr_hash_get(j_provider->value.object, "authorization_endpoint", APR_HASH_KEY_STRING);
	if ( (j_authorization_endpoint == NULL) || (j_authorization_endpoint->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: provider JSON object did not contain an \"authorization_endpoint\" string");
		return FALSE;
	}

	/* get a handle to the token endpoint */
	apr_json_value_t *j_token_endpoint = apr_hash_get(j_provider->value.object, "token_endpoint", APR_HASH_KEY_STRING);
	if ( (j_token_endpoint == NULL) || (j_token_endpoint->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: provider JSON object did not contain a \"token_endpoint\" string");
		return FALSE;
	}

	/* get a handle to the user_info endpoint */
	apr_json_value_t *j_userinfo_endpoint = apr_hash_get(j_provider->value.object, "userinfo_endpoint", APR_HASH_KEY_STRING);
	if ( (j_userinfo_endpoint == NULL) || (j_userinfo_endpoint->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: provider JSON object did not contain a \"userinfo_endpoint\" string");
		return FALSE;
	}

	/* find out what type of authentication we must provide to the token endpoint (we only support post or basic) */
	const char *auth = "client_secret_basic";
	apr_json_value_t *j_token_endpoint_auth_methods_supported = apr_hash_get(j_provider->value.object, "token_endpoint_auth_methods_supported", APR_HASH_KEY_STRING);
	if ( (j_token_endpoint_auth_methods_supported == NULL) || (j_token_endpoint_auth_methods_supported->type != APR_JSON_ARRAY) ) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_metadata_get: provider JSON object did not contain a \"token_endpoint_auth_methods_supported\" array");
	} else {
		int i;
		for (i = 0; i < j_token_endpoint_auth_methods_supported->value.array->nelts; i++) {
			apr_json_value_t *elem = APR_ARRAY_IDX(j_token_endpoint_auth_methods_supported->value.array, i, apr_json_value_t *);
			if (elem->type != APR_JSON_STRING) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: unhandled in-array JSON object type [%d] in provider metadata for entry \"token_endpoint_auth_methods_supported\"", elem->type);
				continue;
			}
			if (strcmp(elem->value.string.p, "client_secret_post") == 0) {
				auth = "client_secret_post";
				break;
			}
			if (strcmp(elem->value.string.p, "client_secret_basic") == 0) {
				auth = "client_secret_basic";
				break;
			}
		}
		if (i == j_token_endpoint_auth_methods_supported->value.array->nelts) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: could not find a supported value [client_secret_post|client_secret_basic] in provider metadata for entry \"token_endpoint_auth_methods_supported\"");
			return FALSE;
		}
	}

	/* put whatever we've found out about the provider in (the provider part of) the metadata struct */
	provider->issuer = apr_pstrdup(r->pool, j_issuer->value.string.p);
	provider->authorization_endpoint_url = apr_pstrdup(r->pool, j_authorization_endpoint->value.string.p);
	provider->token_endpoint_url = apr_pstrdup(r->pool, j_token_endpoint->value.string.p);
	provider->token_endpoint_auth = apr_pstrdup(r->pool, auth);
	provider->userinfo_endpoint_url = apr_pstrdup(r->pool, j_userinfo_endpoint->value.string.p);;

	// CLIENT

	/* find out if we need to perform SSL server certificate validation on the token_endpoint and user_info_endpoint for this provider */
	int validate = cfg->provider.ssl_validate_server;
	apr_json_value_t *j_ssl_validate_server = apr_hash_get(j_client->value.object, "ssl_validate_server", APR_HASH_KEY_STRING);
	if ( (j_ssl_validate_server != NULL) && (j_ssl_validate_server->type == APR_JSON_STRING) && (strcmp(j_ssl_validate_server->value.string.p, "Off") == 0)) {
		validate = 0;
	}

	/* get a handle to the client_id we need to use for this provider */
	apr_json_value_t *j_client_id = apr_hash_get(j_client->value.object, "client_id", APR_HASH_KEY_STRING);
	if ( (j_client_id == NULL) || (j_client_id->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: client JSON object did not contain a \"client_id\" string");
		return FALSE;
	}

	/* get a handle to the client_secret we need to use for this provider */
	apr_json_value_t *j_client_secret = apr_hash_get(j_client->value.object, "client_secret", APR_HASH_KEY_STRING);
	if ( (j_client_secret == NULL) || (j_client_secret->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_metadata_get: client JSON object did not contain a \"client_secret\" string");
		return FALSE;
	}

	/* find out what scopes we should be requesting from this provider */
	// TODO: use the provider "scopes_supported" to mix-and-match with what we've configured for the client
	// TODO: check that "openid" is always included in the configured scopes, right?
	const char *scope = cfg->provider.scope;
	apr_json_value_t *j_scope = apr_hash_get(j_client->value.object, "scope", APR_HASH_KEY_STRING);
	if ( (j_scope != NULL) && (j_scope->type == APR_JSON_STRING) ) {
		scope = j_scope->value.string.p;
	}

	/* put whatever we've found out about the provider in (the client part of) the metadata struct */
	provider->ssl_validate_server = validate;
	provider->client_id = apr_pstrdup(r->pool, j_client_id->value.string.p);
	provider->client_secret = apr_pstrdup(r->pool, j_client_secret->value.string.p);
	provider->scope = apr_pstrdup(r->pool, scope);

	return rc;
}

