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
 *
 * mod_oidc is an Apache authentication/authorization module that allows an Apache server
 * to operate as an OpenID Connect Relying Party, i.e. requires users to authenticate to the
 * Apache hosted content through an external OpenID Connect Identity Provider using the OpenID
 * Connect Basic Client profile (cq. a backchannel flow aka. "code" flow).
 * 
 * Version 1.2 - sets the REMOTE_USER variable to the id_token sub claim, other id_token claims
 * are passed in HTTP headers, together with those (optionally) obtained from the user info endpoint
 * 
 * Todo for version 1.3: allow for authorization rules (based on Requires primitive) that
 * can do matching against the set of claims provided in the id_token/userinfo.
 *
 * Todo for version 2.0: pass on attributes to Apache using mem_cache (or similar,
 * such as the shared filesystem approach that mod_auth_cas uses)
 * 
 * Largely based on mod_auth_cas.c:
 * https://github.com/Jasig/mod_auth_cas
 *
 * Other code copied/borrowed/adapted:
 * JSON decoding: apr_json.h apr_json_decode.c: https://github.com/moriyoshi/apr-json/
 * AES crypto: http://saju.net.in/code/misc/openssl_aes.c.txt
 *
 * Example config for using Google Apps as your OpenID OP:
 * (running on localhost and https://localhost/example registerd as redirect_uri for the client)
 *
 * ==========================================================
 * LoadModule oidc_module modules/mod_oidc.so
 *
 * OIDCClientID <your-client-id-administered-through-the-google-api-console>
 * OIDCClientSecret <your-client-secret-administered-through-the-google-api-console>
 * OIDCIssuer accounts.google.com
 * OIDCAuthorizationEndpoint https://accounts.google.com/o/oauth2/auth?hd=<your-domain>&approval_prompt=force
 * OIDCRedirectURI https://localhost/example
 * OIDCTokenEndpoint https://accounts.google.com/o/oauth2/token
 * OIDCCryptoPassphrase <some-generated-password>
 * OIDCUserInfoEndpoint https://www.googleapis.com/oauth2/v3/userinfo
 * OIDCScope "openid email profile"
 *
 * <Location /example/>
 *    Authtype openid-connect
 *    require valid-user
 * </Location>
 * ==========================================================
 *
 **************************************************************************/

#include "apr_hash.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "apr_lib.h"
#include "apr_file_io.h"
#include "apr_sha1.h"
#include "apr_base64.h"

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "apr_json.h"

#include "mod_oidc.h"
#include "oidc_crypto.h"
#include "oidc_config.h"
#include "oidc_util.h"

extern module AP_MODULE_DECLARE_DATA oidc_module;

// TODO: require SSL

apr_table_t *oidc_scrub_headers(
		apr_pool_t *p,
		const char *const attr_prefix,
		const char *const authn_header,
		const apr_table_t *const headers,
		const apr_table_t **const dirty_headers_ptr
		) {
	const apr_array_header_t *const h = apr_table_elts(headers);
	const int prefix_len = attr_prefix ? strlen(attr_prefix) : 0;

	/* Each header from the headers table is put in one of these two
	   buckets. If the header would be interpreted as an OIDC attribute,
	   and it wasn't set by this module, then it gets put in the dirty
	   bucket. */
	apr_table_t *clean_headers = apr_table_make(p, h->nelts);
	apr_table_t *dirty_headers =
		dirty_headers_ptr ? apr_table_make(p, h->nelts) : NULL;

	/* Loop state */
	const apr_table_entry_t *const e = (const apr_table_entry_t *)h->elts;
	int i;

	for (i = 0; i < h->nelts; i++) {
		const char *const k = e[i].key;

		/* Is this header's name equivalent to the header that OIDC
		 * would set for the authenticated user? */
		const int authn_header_matches =
			(k != NULL) &&
			authn_header &&
			(oidc_strnenvcmp(k, authn_header, -1) == 0);

		/* Would this header be interpreted as a OIDC attribute? Note
		 * that prefix_len will be zero if no attr_prefix is defined,
		 * so this will always be false. Also note that we do not
		 * scrub headers if the prefix is empty because every header
		 * would match.
		 */
		const int prefix_matches =
			(k != NULL) &&
			prefix_len &&
			(oidc_strnenvcmp(k, attr_prefix, prefix_len) == 0);

		/* Is this header a spoofed OIDCAuthNHeader or a spoofed OIDC
		 * attribute header? */
		const int should_scrub = prefix_matches || authn_header_matches;

		/* If it's a spoofed header, put it in the dirty bucket. If it
		 * is not, put it in the clean bucket. */
		apr_table_t *const target =
			should_scrub ? dirty_headers : clean_headers;

		/* The target might be the dirty_headers table, and if the
		 * caller doesn't want to see the dirty headers, then we
		 * should skip that work. */
		if (target) {
			apr_table_addn(target, k, e[i].val);
		}
	}

	/* If the caller wants the dirty headers, then give them a
	 * pointer. */
	if (dirty_headers_ptr) {
		*dirty_headers_ptr = dirty_headers;
	}
	return clean_headers;
}

void oidc_scrub_request_headers(request_rec *r, const oidc_cfg *const c, const oidc_dir_cfg *const d) {
	const apr_table_t *dirty_headers;
	const char *log_fmt;
	const apr_array_header_t *h;
	const apr_table_entry_t *e;
	int i;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_scrub_request_headers()");

	r->headers_in =
		oidc_scrub_headers(
			r->pool,
			c->attribute_prefix,
			d->authn_header,
			r->headers_in,
			&dirty_headers);

	log_fmt =
		"MOD_OIDC: Scrubbed suspicious request header (%s: %.32s)";
	h = apr_table_elts(dirty_headers);
	e = (const apr_table_entry_t *)h->elts;
	for (i = 0; i < h->nelts; i++) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, log_fmt, e[i].key, e[i].val);
	}
}

apr_byte_t oidc_get_code_and_state(request_rec *r, char **code, char **state) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_get_code_and_state()");

	*code = NULL;
	*state = NULL;

	char *tokenizer_ctx, *p, *args, *rv = NULL;
	const char *k_code_param = "code=";
	const size_t k_code_param_sz = strlen(k_code_param);
	const char *k_state_param = "state=";
	const size_t k_state_param_sz = strlen(k_state_param);

	if (r->args == NULL || strlen(r->args) == 0) return FALSE;

	args = apr_pstrndup(r->pool, r->args, strlen(r->args));

	p = apr_strtok(args, "&", &tokenizer_ctx);
	do {
		if (p && strncmp(p, k_code_param, k_code_param_sz) == 0) {
			*code = apr_pstrdup(r->pool, p + k_code_param_sz);
			ap_unescape_url(*code);
		}
		if (p && strncmp(p, k_state_param, k_state_param_sz) == 0) {
			*state = apr_pstrdup(r->pool, p + k_state_param_sz);
			ap_unescape_url(*state);
		}
		p = apr_strtok(NULL, "&", &tokenizer_ctx);
	} while (p);

	if ( (*code == NULL) || (*state == NULL) ) {
		if (*code != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_get_code_and_state: \"code\" parameter found at redirect_uri, but no \"state\" parameter...");
		}
		if (*state != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_get_code_and_state: \"state\" parameter found at redirect_uri, but no \"code\" parameter...");
		}
		return FALSE;
	}
	return TRUE;
}

void oidc_parse_attributes_to_table(request_rec *r, oidc_cfg *c, apr_json_value_t *payload, apr_table_t **attrs, const char *skip) {
	if (*attrs == NULL) *attrs = apr_table_make(r->pool, 5);
	apr_hash_index_t *hi;
	for (hi = apr_hash_first(r->pool, payload->value.object); hi; hi = apr_hash_next(hi)) {
		const char *k; apr_json_value_t *v;
		apr_hash_this(hi, (const void**)&k, NULL, (void**)&v);
		if (strstr(skip, apr_pstrcat(r->pool, k, ",", NULL))) continue;
		if (v->type == APR_JSON_STRING) {
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "### setting attribute %s=%s", k, v->value.string.p);
			apr_table_set(*attrs, k, v->value.string.p);
		} else if (v->type == APR_JSON_ARRAY) {
			char *csvs = apr_pstrdup(r->pool, "");
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "### parsing attribute array %s (#%d)", k, v->value.array->nelts);
			for (int i = 0; i < v->value.array->nelts; i++) {
				apr_json_value_t *elem = APR_ARRAY_IDX(v->value.array, i, apr_json_value_t *);
				if (elem->type == APR_JSON_STRING) {
					// TODO: escape the delimiter in the values
					if (apr_strnatcmp(csvs, "") != 0) {
						csvs = apr_psprintf(r->pool, "%s%s%s", csvs, c->attribute_delimiter, elem->value.string.p);
					} else {
						csvs = apr_psprintf(r->pool, "%s", elem->value.string.p);
					}
				} else {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unhandled in-array JSON object type [%d] when parsing attributes", elem->type);
				}
			}
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "### setting multi-valued attribute %s=%s", k, csvs);
			apr_table_setn(*attrs, k, csvs);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unhandled JSON object type [%d] when parsing attributes", v->type);
		}
	}
}

// TODO: when encrypted, we don't need to aud/check the cookie anymore
// TODO: split out checks into separate functions
int oidc_parse_id_token(request_rec *r, const char *id_token, char **user, apr_table_t **attrs) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);

	const char *s = id_token;
	char *p = strchr(s, '.');
	if (p == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "could not find first \".\" in id_token");
		return FALSE;
	}
	*p = '\0';

	char *dheader = NULL;
	oidc_base64url_decode(r, &dheader, s, 1);
	apr_json_value_t *header = NULL;
	apr_status_t status = apr_json_decode(&header, dheader, strlen(dheader), r->pool);
	if (status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "could not decode header from id_token successfully");
		return FALSE;
	}
	if ( (header ==NULL) || (header->type != APR_JSON_OBJECT) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "header from id_token did not contain a JSON object");
		return FALSE;
	}

	s = ++p;
	p = strchr(s, '.');
	if (p == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "could not find second \".\" in id_token");
		return FALSE;
	}
	*p = '\0';

	char *dpayload = NULL;
	oidc_base64url_decode(r, &dpayload, s, 1);
	apr_json_value_t *payload = NULL;
	status = apr_json_decode(&payload, dpayload, strlen(dpayload), r->pool);
	if (status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "could not decode payload from id_token successfully");
		return FALSE;
	}
	if ( (payload ==NULL) || (payload->type != APR_JSON_OBJECT) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "payload from id_token did not contain a JSON object");
		return FALSE;
	}

	s = ++p;
	char *signature = apr_pstrdup(r->pool, s);

	apr_json_value_t *iss = apr_hash_get(payload->value.object, "iss", APR_HASH_KEY_STRING);
	if ( (iss == NULL) || (iss->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "response JSON object did not contain an \"iss\" string");
		return FALSE;
	}
	if (strcmp(c->issuer, iss->value.string.p) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Configured OIDCIssuer (%s) does not match received \"iss\" value in id_token (%s)", c->issuer, iss->value.string.p);
		return FALSE;
	}

	apr_json_value_t *exp = apr_hash_get(payload->value.object, "exp", APR_HASH_KEY_STRING);
	if ( (exp == NULL) || (exp->type != APR_JSON_LONG) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "response JSON object did not contain an \"exp\" number");
		return FALSE;
	}
	if (apr_time_now() / APR_USEC_PER_SEC > exp->value.lnumber) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "id_token expired");
		return FALSE;
	}

	apr_json_value_t *aud = apr_hash_get(payload->value.object, "aud", APR_HASH_KEY_STRING);
	if ( aud != NULL) {
		if (aud->type == APR_JSON_STRING) {
			if (strcmp(aud->value.string.p, c->client_id) != 0) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "our client_id (%s) did not match the JSON \"aud\" entry (%s)", c->client_id, aud->value.string.p);
				return FALSE;
			}
		} else if (aud->type == APR_JSON_ARRAY) {

			apr_json_value_t *azp = apr_hash_get(payload->value.object, "azp", APR_HASH_KEY_STRING);
			if (azp == NULL) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "\"aud\" is an array, but \"azp\" claim is not present; that is a spec violation...");
				return FALSE;
			}
			int i;
			for (i = 0; i < aud->value.array->nelts; i++) {
				apr_json_value_t *elem = APR_ARRAY_IDX(aud->value.array, i, apr_json_value_t *);
				if (elem->type != APR_JSON_STRING) {
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Unhandled in-array JSON object type [%d]", elem->type);
					continue;
				}
				if (strcmp(elem->value.string.p, c->client_id) == 0) {
					break;
				}
			}
			if (i == aud->value.array->nelts) {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "our client_id (%s) could not be found in the JSON \"aud\" array object", c->client_id);
				return FALSE;
			}
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "response JSON \"aud\" object is not a string nor an array");
			return FALSE;
		}
	} else {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "response JSON object did not contain an \"aud\" element");
		return FALSE;
	}

	apr_json_value_t *azp = apr_hash_get(payload->value.object, "azp", APR_HASH_KEY_STRING);
	if ( (azp != NULL) && (azp->type != APR_JSON_STRING) ) {
		if (strcmp(azp->value.string.p, c->client_id) != 0) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "\"azp\" claim (%s) is not equal to our client_id (%s)", azp->value.string.p, c->client_id);
			return FALSE;
		}
	}

	apr_json_value_t *username = apr_hash_get(payload->value.object, "sub", APR_HASH_KEY_STRING);
	if ( (username == NULL) || (username->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "response JSON object did not contain a \"sub\" string");
		return FALSE;
	}

	ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "### valid id_token for user \"%s\" (expires in %ld seconds)", username->value.string.p, exp->value.lnumber - apr_time_now() / APR_USEC_PER_SEC);

	*user = apr_pstrdup(r->pool, username->value.string.p);

	oidc_parse_attributes_to_table(r, c, payload, attrs, "iss,sub,aud,nonce,exp,iat,azp,at_hash,c_hash,");

	return 0;
}

apr_byte_t oidc_json_string_print(request_rec *r, apr_json_value_t *result, const char *key, const char *log) {
	apr_json_value_t *value = apr_hash_get(result->value.object, key, APR_HASH_KEY_STRING);
	if (value != NULL) {
		if (value->type == APR_JSON_STRING) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s: response contained a \"%s\" key with string value: \"%s\"", log, key, value->value.string.p);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "%s: response contained an \"%s\" key but no string value", log, key);
		}
		return TRUE;
	}
	return FALSE;
}

apr_byte_t oidc_json_error_check(request_rec *r, apr_json_value_t *result, const char *log) {
	if (oidc_json_string_print(r, result, "error", log) == TRUE) {
		oidc_json_string_print(r, result, "error_description", log);
		return FALSE;
	}
	return TRUE;
}

apr_byte_t oidc_resolve_code(request_rec *r, oidc_cfg *c, oidc_dir_cfg *d, char *code, char **user, apr_table_t **attrs, char **s_id_token, char **s_access_token) {

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_resolve_code(): entering");

	char *postfields = apr_psprintf(r->pool,
			"grant_type=authorization_code&code=%s&redirect_uri=%s",
			oidc_escape_string(r, code),
			oidc_escape_string(r, apr_uri_unparse(r->pool, &c->redirect_uri, 0))
	);
	if ((apr_strnatcmp(c->token_endpoint_auth, "client_secret_post")) == 0) {
		postfields = apr_psprintf(r->pool, "%s&client_id=%s&client_secret=%s", postfields, oidc_escape_string(r, c->client_id), oidc_escape_string(r, c->client_secret));
	}
	const char *response = oidc_http_call(r, c, apr_uri_unparse(r->pool, &c->token_endpoint_url, 0), postfields, (apr_strnatcmp(c->token_endpoint_auth, "client_secret_basic") == 0), NULL);
	if (response == NULL)
		return FALSE;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_resolve_code(): response = %s", response);

	apr_json_value_t *result = NULL;
	apr_status_t status = apr_json_decode(&result, response, strlen(response), r->pool);

	if (status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_resolve_code(): could not decode response successfully");
		return FALSE;
	}

	if ( (result ==NULL) || (result->type != APR_JSON_OBJECT) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_resolve_code(): response did not contain a JSON object");
		return FALSE;
	}

	if (oidc_json_error_check(r, result, "oidc_resolve_code()") == FALSE) return FALSE;

	// at_hash is optional

	apr_json_value_t *access_token = apr_hash_get(result->value.object, "access_token", APR_HASH_KEY_STRING);
	if ( (access_token == NULL) || (access_token->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_resolve_code(): response JSON object did not contain an access_token string");
		return FALSE;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_resolve_code(): returned access_token: %s", access_token->value.string.p);
	*s_access_token = apr_pstrdup(r->pool, access_token->value.string.p);

	apr_json_value_t *token_type = apr_hash_get(result->value.object, "token_type", APR_HASH_KEY_STRING);
	if ( (token_type == NULL) || (token_type->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_resolve_code(): response JSON object did not contain a token_type string");
		return FALSE;
	}
	if ((apr_strnatcmp(token_type->value.string.p, "Bearer") != 0) && (oidc_get_endpoint(r, &c->userinfo_endpoint_url, NULL) != NULL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_resolve_code(): token_type is \"%s\" and UserInfo endpoint is set: can only deal with Bearer authentication against the UserInfo endpoint!", token_type->value.string.p);
		//return FALSE;
	}

	apr_json_value_t *id_token = apr_hash_get(result->value.object, "id_token", APR_HASH_KEY_STRING);
	if ( (id_token == NULL) || (id_token->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_resolve_code(): response JSON object did not contain an id_token string");
		return FALSE;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_resolve_code(): returned id_token: %s", id_token->value.string.p);
	*s_id_token = apr_pstrdup(r->pool, id_token->value.string.p);

	oidc_parse_id_token(r, id_token->value.string.p, user, attrs);

	return (status == APR_SUCCESS) ? TRUE : FALSE;
}

apr_byte_t oidc_resolve_userinfo(request_rec *r, oidc_cfg *c, oidc_dir_cfg *d, char **attributes, char *access_token) {
	char *url = oidc_get_endpoint(r, &c->userinfo_endpoint_url, NULL);
	*attributes = (url != NULL) ? oidc_http_call(r, c, url, NULL, 0, access_token) : apr_pstrdup(r->pool, "");
	return TRUE;
}

#define OIDCStateCookieName  "oidc-state"
#define OIDCStateCookieSep  " "
#define OIDCSHA1Len 20
#define OIDCRandomLen 32

char *oidc_get_browser_state_hash(request_rec *r, const char *s) {
	unsigned char hash[OIDCSHA1Len];
	apr_sha1_ctx_t sha1;
	apr_sha1_init(&sha1);
	char *v = (char *) apr_table_get(r->headers_in, "X_FORWARDED_FOR");
	if (v != NULL) apr_sha1_update(&sha1, v, strlen(v));
	v = (char *) apr_table_get(r->headers_in, "USER_AGENT");
	if (v != NULL) apr_sha1_update(&sha1, v, strlen(v));
	apr_sha1_update(&sha1, r->connection->remote_ip, strlen(r->connection->remote_ip));
	apr_sha1_update(&sha1, s, strlen(s));
	apr_sha1_final(hash, &sha1);
	char *result = apr_palloc(r->pool, apr_base64_encode_len(OIDCSHA1Len) +1);
	apr_base64_encode(result, (const char *)hash, OIDCSHA1Len);
	return result;
}

char *oidc_check_state_and_get_url(request_rec *r, char *state) {
	char *result = NULL;
	char *cookieValue = oidc_get_cookie(r, OIDCStateCookieName);
	if (cookieValue == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_check_state_and_get_url: no \"%s\" cookie found.", OIDCStateCookieName);
		return NULL;
	}

	// clear oidc-state cookie
	oidc_set_cookie(r, OIDCStateCookieName, "");

	char *svalue;
	oidc_base64url_decode_decrypt_string(r, &svalue, cookieValue);
	char *ctx = NULL;
	char *b64 = apr_strtok(svalue, OIDCStateCookieSep, &ctx);
	if (b64 == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_check_state_and_get_url: no first element found in \"%s\" cookie (%s).", OIDCStateCookieName, cookieValue);
		return NULL;
	}

	char *calc = oidc_get_browser_state_hash(r, b64);
	if (apr_strnatcmp(calc, state) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_check_state_and_get_url: calculated state from cookie does not match state parameter passed back in URL: \"%s\" != \"%s\"", state, calc);
		return NULL;
	}

	result = apr_strtok(NULL, OIDCStateCookieSep, &ctx);
	if (result == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_check_state_and_get_url: no separator (%s) found in \"%s\" cookie (%s).", OIDCStateCookieSep, OIDCStateCookieName, cookieValue);
		return NULL;
	}
	ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_check_state_and_get_url: original URL restored from cookie: %s.", result);
	return result;
}

char *oidc_create_state_and_set_cookie(request_rec *r, oidc_cfg *c) {
	char *cookieValue = NULL;
	char *url = oidc_get_current_url(r, c);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_create_state_and_set_cookie()");

	unsigned char *brnd = apr_pcalloc(r->pool, OIDCRandomLen);
	apr_generate_random_bytes((unsigned char *) brnd, OIDCRandomLen);
	char *b64 = apr_palloc(r->pool, apr_base64_encode_len(OIDCRandomLen) + 1);
	apr_base64_encode(b64, (const char *)brnd, OIDCRandomLen);

	char *rvalue = apr_psprintf(r->pool, "%s%s%s", b64, OIDCStateCookieSep, url);
	oidc_encrypt_base64url_encode_string(r, &cookieValue, rvalue);
	char *headerString = apr_psprintf(r->pool, "%s=%s%s;Path=%s%s%s", OIDCStateCookieName, cookieValue, ";Secure", oidc_url_encode(r, oidc_get_dir_scope(r), " "), (c->cookie_domain != NULL ? ";Domain=" : ""), (c->cookie_domain != NULL ? c->cookie_domain : ""));
	apr_table_add(r->err_headers_out, "Set-Cookie", headerString);

	return oidc_get_browser_state_hash(r, b64);
}

void oidc_redirect(request_rec *r, oidc_cfg *c) {
	char *destination = NULL, *state = NULL;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_redirect()");
	char *endpoint = oidc_get_endpoint(r, &c->authorization_endpoint_url, "OIDCAuthorizationEndpoint");
	if (endpoint == NULL) return;
	state = oidc_create_state_and_set_cookie(r, c);
	destination = apr_psprintf(r->pool, "%s%sresponse_type=%s&scope=%s&client_id=%s&state=%s&redirect_uri=%s", endpoint, (strchr(endpoint, '?') != NULL ? "&" : "?"), "code", oidc_escape_string(r, c->scope), oidc_escape_string(r, c->client_id), oidc_escape_string(r, state), oidc_escape_string(r, apr_uri_unparse(r->pool, &c->redirect_uri, 0)));
	apr_table_add(r->headers_out, "Location", destination);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Adding outgoing header: Location: %s", destination);

}

apr_byte_t oidc_is_valid_cookie(request_rec *r, oidc_cfg *c, char *cookie, char **user, apr_table_t **attrs) {
	oidc_dir_cfg *d = ap_get_module_config(r->per_dir_config, &oidc_module);
	char *value = NULL;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_is_valid_cookie()");

	if (oidc_base64url_decode_decrypt_string(r, &value, cookie) <= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_is_valid_cookie: could not find decode cookie value");
		return FALSE;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_is_valid_cookie: decrypted cookie value: %s", value);

	char *p = strrchr(value, '.');
	if (p == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_is_valid_cookie: could not find last \".\" in cookie value");
		return FALSE;
	}
	*p = '\0';
	p++;

	char *s = apr_palloc(r->pool, apr_base64_decode_len(p));
	apr_base64_decode(s, p);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_is_valid_cookie: id_token value: %s", value);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_is_valid_cookie: JSON attributes value: %s", s);

	oidc_parse_id_token(r, value, user, attrs);

	if (apr_strnatcmp(s, "") != 0) {
		apr_json_value_t *attributes = NULL;
		apr_status_t status = apr_json_decode(&attributes, s, strlen(s), r->pool);
		if (status != APR_SUCCESS) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_is_valid_cookie: could not decode JSON from UserInfo endpoint response successfully");
			return FALSE;
		}
		if ( (attributes == NULL) || (attributes->type != APR_JSON_OBJECT) ) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_is_valid_cookie: UserInfo endpoint response did not contain a JSON object");
			return FALSE;
		}
		oidc_parse_attributes_to_table(r, c, attributes, attrs, "");
	}

	return TRUE;
}

apr_byte_t oidc_request_matches_redirect_uri(request_rec *r, oidc_cfg *c) {
	char *p1 = r->parsed_uri.path;
	char *p2 = c->redirect_uri.path;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_request_matches_redirect_uri(): comparing \"%s\"==\"%s\"", p1, p2);
	return (apr_strnatcmp(p1, p2) == 0) ? TRUE : FALSE;
}

int oidc_check_user_id(request_rec *r) {
	char *code = NULL, *state = NULL;
	char *cookieString = NULL;
	char *remoteUser = NULL;
	apr_table_t *attrs = NULL;

	oidc_cfg *c;
	oidc_dir_cfg *d;

	if (ap_auth_type(r) == NULL || apr_strnatcasecmp((const char *) ap_auth_type(r), "openid-connect") != 0)
		return DECLINED;

	c = ap_get_module_config(r->server->module_config, &oidc_module);
	d = ap_get_module_config(r->per_dir_config, &oidc_module);

	if (ap_is_initial_req(r) && d->scrub_request_headers) {
		oidc_scrub_request_headers(r, c, d);
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Entering oidc_check_user_id()");

	cookieString = oidc_get_cookie(r, d->cookie);

	// check that the request path matches the configured redirect URI, otherwise a regular
	// protected URL can't have a code= parameter without it being interpreted as an OIDC callback
	if (oidc_request_matches_redirect_uri(r, c) == TRUE) {
		if (oidc_get_code_and_state(r, &code, &state) == TRUE) {
			char *original_url = oidc_check_state_and_get_url(r, state);
			if (original_url == NULL) return HTTP_UNAUTHORIZED;
			char *id_token = NULL, *access_token = NULL, *attributes = NULL;
			if (oidc_resolve_code(r, c, d, code, &remoteUser, &attrs, &id_token, &access_token)) {

				oidc_resolve_userinfo(r, c, d, &attributes, access_token);
				char *b64 = apr_palloc(r->pool, apr_base64_encode_len(strlen(attributes)));
				apr_base64_encode(b64, attributes, strlen(attributes));
				char *crypted = NULL;
				oidc_encrypt_base64url_encode_string(r, &crypted, apr_psprintf(r->pool, "%s.%s", id_token, b64));

				oidc_set_cookie(r, d->cookie, crypted);
				r->user = remoteUser;
				if (d->authn_header != NULL)
					apr_table_set(r->headers_in, d->authn_header, remoteUser);
				// NB: no oidc_set_attribute_headers(r, attrs) here because of the redirect that follows
				apr_table_add(r->headers_out, "Location", original_url);
				return HTTP_MOVED_TEMPORARILY;
			} else {
				/* sometimes, pages that automatically refresh will re-send the code parameter, so let's check any cookies presented or return an error if none */
				if (cookieString == NULL)
					return HTTP_UNAUTHORIZED;
			}
		}
	}

	if (cookieString == NULL) {
		/* redirect the user to the OIDC OP  since they have no cookie and no ticket */
		oidc_redirect(r, c);
		return HTTP_MOVED_TEMPORARILY;
	} else {
		if (!ap_is_initial_req(r)) {
			if (r->main != NULL)
				remoteUser = r->main->user;
			else if (r->prev != NULL)
				remoteUser = r->prev->user;
			else {
				oidc_redirect(r, c);
				return HTTP_MOVED_TEMPORARILY;
			}
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "recycling user '%s' from initial request for sub request", remoteUser);
		} else if (!oidc_is_valid_cookie(r, c, cookieString, &remoteUser, &attrs)) {
			remoteUser = NULL;
		}

		if (remoteUser) {
			r->user = remoteUser;
			if (d->authn_header != NULL) {
				apr_table_set(r->headers_in, d->authn_header, remoteUser);
 			}
			oidc_set_attribute_headers(r, attrs);
			return OK;
		} else {
			/* maybe the cookie expired, have the user re-authenticate */
			oidc_redirect(r, c);
			return HTTP_MOVED_TEMPORARILY;
		}
	}

	return HTTP_UNAUTHORIZED;
}

int oidc_auth_checker(request_rec *r) {
	// TODO: when attributes are resolved and stored (copy the file caching mechanism from mod_auth_cas...)
	// we can parse expressions here that match and autorize on attributes
	return DECLINED;
}

const command_rec oidc_config_cmds[] = {
		AP_INIT_FLAG("OIDCSSLValidateServer", oidc_set_flag_slot, (void*)APR_OFFSETOF(oidc_cfg, ssl_validate_server), RSRC_CONF, "Require validation of the OpenID Connect OP SSL server certificate for successful authentication (On or Off)"),
		AP_INIT_TAKE1("OIDCClientID", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, client_id), RSRC_CONF, "Client identifier used in calls to OpenID Connect OP."),
		AP_INIT_TAKE1("OIDCClientSecret", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, client_secret), RSRC_CONF, "Client secret used in calls to OpenID Connect OP."),
		AP_INIT_TAKE1("OIDCRedirectURI", oidc_set_uri_slot, (void *)APR_OFFSETOF(oidc_cfg, redirect_uri), RSRC_CONF, "Define the Redirect URI (e.g.: https://localhost:9031/protected/return/uri"),
		AP_INIT_TAKE1("OIDCIssuer", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, issuer), RSRC_CONF, "OpenID Connect OP issuer identifier."),
		AP_INIT_TAKE1("OIDCAuthorizationEndpoint", oidc_set_uri_slot, (void *)APR_OFFSETOF(oidc_cfg, authorization_endpoint_url), RSRC_CONF, "Define the OpenID OP Authorization Endpoint URL (e.g.: https://localhost:9031/as/authorization.oauth2)"),
		AP_INIT_TAKE1("OIDCTokenEndpoint", oidc_set_uri_slot, (void *)APR_OFFSETOF(oidc_cfg, token_endpoint_url), RSRC_CONF, "Define the OpenID OP Token Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
		AP_INIT_TAKE1("OIDCTokenEndpointAuth", oidc_set_token_endpoint_auth, NULL, RSRC_CONF, "Specify an authentication method for the OpenID OP Token Endpoint (e.g.: client_auth_basic)"),
		AP_INIT_TAKE1("OIDCUserInfoEndpoint", oidc_set_uri_slot, (void *)APR_OFFSETOF(oidc_cfg, userinfo_endpoint_url), RSRC_CONF, "Define the OpenID OP UserInfo Endpoint URL (e.g.: https://localhost:9031/idp/userinfo.openid)"),
		AP_INIT_TAKE1("OIDCCookieDomain", oidc_set_cookie_domain, NULL, RSRC_CONF, "Specify domain element for OIDC session cookie."),
		AP_INIT_TAKE1("OIDCCryptoPassphrase", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, crypto_passphrase), RSRC_CONF, "Passphrase used for AES crypto on cookies and state."),
		AP_INIT_TAKE1("OIDCAttributeDelimiter", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, attribute_delimiter), RSRC_CONF, "The delimiter to use when setting multi-valued attributes in the HTTP headers."),
		AP_INIT_TAKE1("OIDCAttributePrefix ", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, attribute_prefix), RSRC_CONF, "The prefix to use when setting attributes in the HTTP headers."),
		AP_INIT_TAKE1("OIDCScope", oidc_set_string_slot, (void *) APR_OFFSETOF(oidc_cfg, scope), RSRC_CONF, "Define the OpenID Connect scope that is requested from the OP."),

		AP_INIT_TAKE1("OIDCAuthNHeader", ap_set_string_slot, (void *) APR_OFFSETOF(oidc_dir_cfg, authn_header), ACCESS_CONF|OR_AUTHCFG, "Specify the HTTP header variable to set with the name of the OIDC authenticated user.  By default no headers are added."),
		AP_INIT_TAKE1("OIDCScrubRequestHeaders", ap_set_string_slot, (void *) APR_OFFSETOF(oidc_dir_cfg, scrub_request_headers), ACCESS_CONF, "Scrub OIDC user name and ID_TOKEN attribute headers from the user's request."),
		AP_INIT_TAKE1("OIDCDirScope", ap_set_string_slot, (void *) APR_OFFSETOF(oidc_dir_cfg, dir_scope), ACCESS_CONF|OR_AUTHCFG, "Define the OpenID Connect scope."),
		AP_INIT_TAKE1("OIDCCookie", ap_set_string_slot, (void *) APR_OFFSETOF(oidc_dir_cfg, cookie), ACCESS_CONF|OR_AUTHCFG, "Define the cookie name for HTTP sessions"),
		{ NULL }
};

module AP_MODULE_DECLARE_DATA oidc_module = {
	STANDARD20_MODULE_STUFF,
	oidc_create_dir_config,
	oidc_merge_dir_config,
	oidc_create_server_config,
	oidc_merge_server_config,
	oidc_config_cmds,
	oidc_register_hooks
};
