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

#include <apr_lib.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include "mod_oidc.h"

/* the grant type string that the Authorization server expects when validating access tokens */
#define OIDC_OAUTH_VALIDATION_GRANT_TYPE "urn:pingidentity.com:oauth2:grant_type:validate_bearer"

/*
 * validates an access token against the validation endpoint of the Authorization server and gets a response back
 */
static int oidc_oauth_validate_access_token (request_rec *r, oidc_cfg *c, const char *token, const char **response) {
	char *result = NULL;
	const char *url = c->oauth.validate_endpoint_url;
	char *postfields = NULL;

	if ((apr_strnatcmp(c->oauth.validate_endpoint_auth, "client_secret_post")) == 0) {

		/* assemble post parameters */
		postfields = apr_psprintf(r->pool, "grant_type=%s&token=%s&client_id=%s&client_secret=%s", oidc_escape_string(r, OIDC_OAUTH_VALIDATION_GRANT_TYPE), oidc_escape_string(r, token), oidc_escape_string(r, c->oauth.client_id), oidc_escape_string(r, c->oauth.client_secret));
	} else {

		/* use HTTP basic auth and assemble parameters in the query part of the URL */
		url = apr_psprintf(r->pool, "%s%sgrant_type=%s&token=%s", url, strchr(c->oauth.validate_endpoint_url, '?') != NULL ? "&" : "?", OIDC_OAUTH_VALIDATION_GRANT_TYPE, token);
	}

	/* call the endpoint with the constructed parameter set and return the resulting response */
	*response = oidc_http_call(r, url, postfields, (apr_strnatcmp(c->oauth.validate_endpoint_auth, "client_secret_basic") == 0) ? apr_psprintf(r->pool, "%s:%s", c->oauth.client_id, c->oauth.client_secret) : NULL, NULL, c->oauth.ssl_validate_server);

	return (*response != NULL) ? TRUE : FALSE;
}

/*
 * get the authorization header that should contain a bearer token
 */
static apr_byte_t oidc_oauth_get_bearer_token(request_rec *r, const char **access_token) {

	/* get the authorization header */
	const char *auth_line;
	auth_line = apr_table_get(r->headers_in, "Authorization");
	if (!auth_line) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_oauth_get_bearer_token: no authorization header found");
		return FALSE;
	}

	/* look for the Bearer keyword */
	if (strcasecmp(ap_getword(r->pool, &auth_line, ' '), "Bearer")) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_oauth_get_bearer_token: client used unsupported authentication scheme: %s", r->uri);
		return FALSE;
	}

	/* skip any spaces after the Bearer keyword */
	while (apr_isspace(*auth_line)) {
		auth_line++;
	}

	/* copy the result in to the access_token */
	*access_token = apr_pstrdup(r->pool, auth_line);

	/* log some stuff */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_oauth_get_bearer_token: bearer token: %s", *access_token);

	return TRUE;
}

static apr_byte_t oidc_oauth_resolve_access_token(request_rec *r, oidc_cfg *c, const char *access_token, apr_json_value_t **token) {

	apr_json_value_t *result = NULL;
	const char *json = NULL;

	/* see if we've got the claims for this access_token cached already */
	oidc_cache_get(r, access_token, &json);

	if (json == NULL) {

		/* not cached, go out and validate the access_token against the Authorization server and get the JSON claims back */
		if (oidc_oauth_validate_access_token(r, c, access_token, &json) == FALSE) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_oauth_resolve_access_token: could not get a validation response from the Authorization server");
			return FALSE;
		}

		/* decode the response in to a JSON structure */
		if (apr_json_decode(&result, json, strlen(json), r->pool) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_oauth_resolve_access_token: could not JSON decode response successfully");
			return FALSE;
		}
		if ( (result ==NULL) || (result->type != APR_JSON_OBJECT) ) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_oauth_resolve_access_token: response did not contain a JSON object");
			return FALSE;
		}

		if (oidc_util_check_json_error(r, result)) return FALSE;

		/* get and check the expiry timestamp */
		apr_json_value_t *expires_in = apr_hash_get(result->value.object, "expires_in", APR_HASH_KEY_STRING);
		if ( (expires_in == NULL) || (expires_in->type != APR_JSON_LONG) ) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_oauth_resolve_access_token: response JSON object did not contain an \"expires_in\" number");
			return FALSE;
		}
		if (expires_in->value.lnumber <= 0) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "oidc_oauth_resolve_access_token: \"expires_in\" number <= 0 (%ld); token already expired...", expires_in->value.lnumber);
			return FALSE;
		}

		/* set it in the cache so subsequent request don't need to validate the access_token and get the claims anymore */
		oidc_cache_set(r, access_token, json, apr_time_now() + apr_time_from_sec(expires_in->value.lnumber));

	} else {

		/* we got the claims for this access_token in our cache, decode it in to a JSON structure */
		if (apr_json_decode(&result, json, strlen(json), r->pool) != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_oauth_resolve_access_token: cached JSON was corrupted");
			return FALSE;
		}
		/* the NULL and APR_JSON_OBJECT checks really are superfluous here */
	}

	/* return the access_token JSON object */
	*token = apr_hash_get(result->value.object, "access_token", APR_HASH_KEY_STRING);
	if ( (*token == NULL) || ((*token)->type != APR_JSON_OBJECT) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_oauth_resolve_access_token: response JSON object did not contain an access_token object");
		return FALSE;
	}

	return TRUE;
}

int oidc_oauth_check_userid(request_rec *r, oidc_cfg *c) {

	char *decoded_line;
	int length;

	/* check if this is a sub-request or an initial request */
	if (!ap_is_initial_req(r)) {

		if (r->main != NULL)
			r->user = r->main->user;
		else if (r->prev != NULL)
			r->user= r->prev->user;

		if (r->user != NULL) {

			/* this is a sub-request and we have a session */
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_oauth_check_userid: recycling user '%s' from initial request for sub-request", r->user);

			return OK;
		}
	}

	/* we don't have a session yet */

	/* get the bearer access token from the Authorization header */
	const char *access_token = NULL;
	if (oidc_oauth_get_bearer_token(r, &access_token) == FALSE) return HTTP_UNAUTHORIZED;

	/* validate the obtained access token against the OAuth AS validation endpoint */
	apr_json_value_t *result, *token = NULL;
	if (oidc_oauth_resolve_access_token(r, c, access_token, &token) == FALSE) return HTTP_UNAUTHORIZED;

	/* store the parsed token (cq. the claims from the response) in the request state so it can be accessed by the authz routines */
	oidc_request_state_set(r, OIDC_CLAIMS_SESSION_KEY, (const char *)token);

	// TODO: user attribute header settings & scrubbing ?

	/* get the username from the response to use as the REMOTE_USER key */
	apr_json_value_t *username = apr_hash_get(token->value.object, "Username", APR_HASH_KEY_STRING);
	if ( (username == NULL) || (username->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_oauth_check_userid: response JSON object did not contain a Username string");
	} else {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_oauth_check_userid: returned username: %s", username->value.string.p);
		r->user = apr_pstrdup(r->pool, username->value.string.p);
	}

	return OK;
}
