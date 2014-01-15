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
 * Initially based on mod_auth_cas.c:
 * https://github.com/Jasig/mod_auth_cas
 *
 * Other code copied/borrowed/adapted:
 * JSON decoding: apr_json.h apr_json_decode.c: https://github.com/moriyoshi/apr-json/
 * AES crypto: http://saju.net.in/code/misc/openssl_aes.c.txt
 * session handling: Apache 2.4 mod_session.c
 * session handling backport: http://contribsoft.caixamagica.pt/browser/internals/2012/apachecc/trunk/mod_session-port/src/util_port_compat.c
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
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

#include "mod_oidc.h"

// TODO: improve error handling/logging consistency and completeness (make #define shortcuts)
// TODO: require SSL
// TODO: user documentation (at least of configuration primitives)
// TODO: fix the http_call SSL error on Ubuntu?

extern module AP_MODULE_DECLARE_DATA oidc_module;

/*
 * clean any suspicious headers in the HTTP request sent by the user agent
 */
static void oidc_scrub_request_headers(request_rec *r, const char *claim_prefix,  const char *authn_header) {

	const int prefix_len = claim_prefix ? strlen(claim_prefix) : 0;

	/* get an array representation of the incoming HTTP headers */
	const apr_array_header_t *const h = apr_table_elts(r->headers_in);

	/* table to keep the non-suspicous headers */
	apr_table_t *clean_headers = apr_table_make(r->pool, h->nelts);

	/* loop over the incoming HTTP headers */
	const apr_table_entry_t *const e = (const apr_table_entry_t *)h->elts;
	int i;
	for (i = 0; i < h->nelts; i++) {
		const char *const k = e[i].key;

		 /* is this header's name equivalent to the header that OIDC would set for the authenticated user? */
		const int authn_header_matches =
			(k != NULL) &&
			authn_header &&
			(oidc_strnenvcmp(k, authn_header, -1) == 0);

		/*
		 * would this header be interpreted as a OIDC attribute? Note
		 * that prefix_len will be zero if no attr_prefix is defined,
		 * so this will always be false. Also note that we do not
		 * scrub headers if the prefix is empty because every header
		 * would match.
		 */
		const int prefix_matches =
			(k != NULL) &&
			prefix_len &&
			(oidc_strnenvcmp(k, claim_prefix, prefix_len) == 0);

		/* add to the clean_headers if non-suspicious, skip and report otherwise */
		if (!prefix_matches && !authn_header_matches) {
			apr_table_addn(clean_headers, k, e[i].val);
		} else {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r, "oidc_scrub_request_headers: scrubbed suspicious request header (%s: %.32s)", k, e[i].val);
		}
	}

	/* overwrite the incoming headrs with the clean result */
	r->headers_in = clean_headers;
}

/*
 * calculates a hash value based on request fingerprint plus a provided state string.
 */
char *oidc_get_browser_state_hash(request_rec *r, const char *state) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_get_browser_state_hash: entering");

	/* helper to hold to header values */
	const char *value = NULL;
	/* the hash context */
	apr_sha1_ctx_t sha1;

	/* initialize the hash context */
	apr_sha1_init(&sha1);

	/* get the X_FORWARDED_FOR header value  */
	value = (char *) apr_table_get(r->headers_in, "X_FORWARDED_FOR");
	/* if we have a value for this header, concat it to the hash input */
	if (value != NULL)
		apr_sha1_update(&sha1, value, strlen(value));

	/* get the USER_AGENT header value  */
	value = (char *) apr_table_get(r->headers_in, "USER_AGENT");
	/* if we have a value for this header, concat it to the hash input */
	if (value != NULL)
		apr_sha1_update(&sha1, value, strlen(value));

	/* get the remote client IP address or host name */
	int remotehost_is_ip;
	value = ap_get_remote_host(r->connection,
			r->per_dir_config, REMOTE_NOLOOKUP, &remotehost_is_ip);
	/* concat the remote IP address/hostname to the hash input */
	apr_sha1_update(&sha1, value, strlen(value));

	/* concat the state parameter to the hash input */
	apr_sha1_update(&sha1, state, strlen(state));

	/* finalize the hash input and calculate the resulting hash output */
	const int sha1_len = 20;
	unsigned char hash[sha1_len];
	apr_sha1_final(hash, &sha1);

	/* base64 encode the resulting hash and return it */
	char *result = apr_palloc(r->pool, apr_base64_encode_len(sha1_len) + 1);
	apr_base64_encode(result, (const char *) hash, sha1_len);
	return result;
}

/*
 * see if the state that came back from the OP matches what we've stored in the cookie
 */
static int oidc_check_state(request_rec *r, char *state, char **original_url, char **issuer) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_check_state: entering");

	/* get the state cookie value first */
	char *cookieValue = oidc_get_cookie(r, OIDCStateCookieName);
	if (cookieValue == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_check_state: no \"%s\" cookie found", OIDCStateCookieName);
		return FALSE;
	}

	/* clear state cookie because we don't need it anymore */
	oidc_set_cookie(r, OIDCStateCookieName, "");

	/* decrypt the state obtained from the cookie */
	char *svalue;
	oidc_base64url_decode_decrypt_string(r, &svalue, cookieValue);

	/* context to iterate over the entries in the decrypted state cookie value */
	char *ctx = NULL;

	/* first get the base64-encoded random value */
	char *b64 = apr_strtok(svalue, OIDCStateCookieSep, &ctx);
	if (b64 == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_check_state: no first element found in \"%s\" cookie (%s)", OIDCStateCookieName, cookieValue);
		return FALSE;
	}

	/* calculate the hash of the browser fingerprint concatenated with the random value */
	char *calc = oidc_get_browser_state_hash(r, b64);

	/* compare the calculated hash with the value provided in the authorization response */
	if (apr_strnatcmp(calc, state) != 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_check_state: calculated state from cookie does not match state parameter passed back in URL: \"%s\" != \"%s\"", state, calc);
		return FALSE;
	}

	/* since we're ok, get the orginal URL as the next value in the decrypted cookie */
	*original_url = apr_strtok(NULL, OIDCStateCookieSep, &ctx);
	if (*original_url == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_check_state: no separator (%s) found in \"%s\" cookie (%s)", OIDCStateCookieSep, OIDCStateCookieName, cookieValue);
		return FALSE;
	}
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_check_state: \"original_url\" restored from cookie: %s", *original_url);

	/* lastly, get the issuer as the third and last value stored in the cookie */
	*issuer = apr_strtok(NULL, OIDCStateCookieSep, &ctx);
	if (*issuer == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_check_state: no second separator (%s) found in \"%s\" cookie (%s)", OIDCStateCookieSep, OIDCStateCookieName, cookieValue);
		return FALSE;
	}
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_check_state: \"issuer\" restored from cookie: %s", *issuer);

	/* we've made it */
	return TRUE;
}

/*
 * create a state parameter to be passed in an authorization request to an OP
 * and set a cookie in the browser that is cryptograpically bound to that
 */
static char *oidc_create_state_and_set_cookie(request_rec *r, const char *url, const char *issuer) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_create_state_and_set_cookie: entering");

	/* length of the random input included in the state */
	const int randomLen = 32;
	char *cookieValue = NULL;

	/* generate a 32-byte random base64-encoded value */
	unsigned char *brnd = apr_pcalloc(r->pool, randomLen);
	apr_generate_random_bytes((unsigned char *) brnd, randomLen);
	char *b64 = apr_palloc(r->pool, apr_base64_encode_len(randomLen) + 1);
	apr_base64_encode(b64, (const char *)brnd, randomLen);

	/*
	 * create a cookie consisting of 3 elements:
	 * random value, original URL and issuer separated by a defined separator
	 */
	char *rvalue = apr_psprintf(r->pool, "%s%s%s%s%s", b64, OIDCStateCookieSep, url, OIDCStateCookieSep, issuer);

	/* encrypt the resulting value and set it as a cookie */
	oidc_encrypt_base64url_encode_string(r, &cookieValue, rvalue);
	oidc_set_cookie(r, OIDCStateCookieName, cookieValue);

	/* return a hash value that fingerprints the browser concatenated with the random input */
	return oidc_get_browser_state_hash(r, b64);
}

/*
 * get the mod_oidc related context from the (userdata in the) request
 */
static apr_table_t *oidc_request_state(request_rec *rr) {

	/* our state is always stored in the main request */
	request_rec *r = (rr->main != NULL) ? rr->main : rr;

	/* our state is a table, get it */
	apr_table_t *state = NULL;
	apr_pool_userdata_get((void **)&state, MOD_OIDC_USERDATA_KEY, r->pool);

	/* if it does not exist, we'll create a new table */
	if (state == NULL) {
		state = apr_table_make(r->pool, 5);
		apr_pool_userdata_set(state, MOD_OIDC_USERDATA_KEY, NULL, r->pool);
	}

	/* return the resulting table, always non-null now */
	return state;
}

/*
 * set a name/value pair in the mod_oidc-specific request context
 */
void oidc_request_state_set(request_rec *r, const char *key, const char *value) {

	/* get a handle to the global state, which is a table */
	apr_table_t *state = oidc_request_state(r);

	/* put the name/value pair in that table */
	apr_table_setn(state, key, value);
}

/*
 * get a name/value pair from the mod_oidc-specific request context
 */
const char*oidc_request_state_get(request_rec *r, const char *key) {

	/* get a handle to the global state, which is a table */
	apr_table_t *state = oidc_request_state(r);

	/* return the value from the table */
	return apr_table_get(state, key);
}

/*
 * set an HTTP header to pass information to the application
 */
static void oidc_set_app_header(request_rec *r, const char *s_key, const char *s_value, const char *claim_prefix) {

	/* construct the header name */
	const char *s_name = apr_psprintf(r->pool, "%s%s", claim_prefix, oidc_normalize_header_name(r, s_key));

	/* do some logging about this event */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_set_application_header: setting header %s=%s", s_name, s_value);

	/* now set the actual header name/value */
	apr_table_set(r->headers_in, s_name, s_value);
}

/*
 * set the user/claims information from the session in HTTP headers passed on to the application
 */
static void oidc_set_app_headers(request_rec *r, const apr_json_value_t *j_attrs, const char *authn_header, const char *claim_prefix, const char *claim_delimiter) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_set_app_headers: entering");

	apr_json_value_t *j_value = NULL;
	apr_hash_index_t *hi = NULL;
	const char *s_key = NULL;

	/* set the user authentication HTTP header if set and required */
	if (  (r->user != NULL) && (authn_header != NULL) ) apr_table_set(r->headers_in, authn_header, r->user);

	/* if not attributes are set, nothing needs to be done */
	if (j_attrs == NULL) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_set_app_headers: no attributes to set (j_attrs=NULL)");
		return;
	}

	/* loop over the claims in the JSON structure */
	for (hi = apr_hash_first(r->pool, j_attrs->value.object); hi; hi = apr_hash_next(hi)) {

		/* get the next key/value entry */
		apr_hash_this(hi, (const void**)&s_key, NULL, (void**)&j_value);

		/* check if it is a single value string */
		if (j_value->type == APR_JSON_STRING) {

			/* set the single string in the application header whose name is based on the key and the prefix */
			oidc_set_app_header(r, s_key, j_value->value.string.p, claim_prefix);

		} else if (j_value->type == APR_JSON_BOOLEAN) {

			/* set boolean value in the application header whose name is based on the key and the prefix */
			oidc_set_app_header(r, s_key, j_value->value.boolean ? "1" : "0", claim_prefix);

		/* check if it is a multi-value string */
		} else if (j_value->type == APR_JSON_ARRAY) {

			/* some logging about what we're going to do */
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_set_app_headers: parsing attribute array %s (#%d)", s_key, j_value->value.array->nelts);

			/* string to hold the concatenated array string values */
			char *s_concat = apr_pstrdup(r->pool, "");
			int i = 0;

			/* loop over the array */
			for (i = 0; i < j_value->value.array->nelts; i++) {

				/* get the current element */
				apr_json_value_t *elem = APR_ARRAY_IDX(j_value->value.array, i, apr_json_value_t *);

				/* check if it is a string */
				if (elem->type == APR_JSON_STRING) {

					/* concatenate the string to the s_concat value using the configured separator char */
					// TODO: escape the delimiter in the values (maybe reuse/extract url-formatted code from oidc_session_identity_encode)
					if (apr_strnatcmp(s_concat, "") != 0) {
						s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat, claim_delimiter, elem->value.string.p);
					} else {
						s_concat = apr_psprintf(r->pool, "%s", elem->value.string.p);
					}

				} else if (elem->type == APR_JSON_BOOLEAN) {

					if (apr_strnatcmp(s_concat, "") != 0) {
						s_concat = apr_psprintf(r->pool, "%s%s%s", s_concat, claim_delimiter, j_value->value.boolean ? "1" : "0");
					} else {
						s_concat = apr_psprintf(r->pool, "%s", j_value->value.boolean ? "1" : "0");
					}

				} else {

					/* don't know how to handle a non-string array element */
					ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_set_app_headers: unhandled in-array JSON object type [%d] for key \"%s\" when parsing claims", elem->type, s_key);
				}
			}

			/* set the concatenated string */
			oidc_set_app_header(r, s_key, s_concat, claim_prefix);

		} else {

			/* no string and no array, so unclear how to handle this */
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_set_app_headers: unhandled JSON object type [%d] for key \"%s\" when parsing claims", j_value->type, s_key);
		}
	}
}

/*
 * handle the case where we have identified an existing authentication session for a user
 */
static int oidc_handle_existing_session(request_rec *r, const oidc_cfg *const cfg, session_rec *session) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_handle_existing_session: entering");

	const char *s_attrs = NULL;
	apr_json_value_t *j_attrs = NULL;

	/* get a handle to the director config */
	oidc_dir_cfg *dir_cfg = ap_get_module_config(r->per_dir_config, &oidc_module);

	/*
	 * we're going to pass the information that we have to the application,
	 * but first we need to scrub the headers that we're going to use for security reasons
	 */
	if (cfg->scrub_request_headers != 0) {
		oidc_scrub_request_headers(r, cfg->claim_prefix, dir_cfg->authn_header);
	}

	/* get the string-encoded attributes from the session */
	oidc_session_get(r, session, OIDC_CLAIMS_SESSION_KEY, &s_attrs);

	/* decode the string-encoded attributes in to a JSON structure */
	if ( (s_attrs != NULL) && (apr_json_decode(&j_attrs, s_attrs, strlen(s_attrs), r->pool) != APR_SUCCESS) ) {

		// whoops, attributes have been corrupted
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_handle_existing_session: unable to parse string-encoded claims stored in the session: returning HTTP 500");

		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* pass the user/claims in the session to the application by setting the appropriate headers */
	// TODO: combine already resolved attrs from id_token with those from user_info endpoint
	oidc_set_app_headers(r, j_attrs, dir_cfg->authn_header, cfg->claim_prefix, cfg->claim_delimiter);

	/* set the attributes JSON structure in the request state so it is available for authz purposes later on */
	oidc_request_state_set(r, OIDC_CLAIMS_SESSION_KEY, (const char *)j_attrs);

	/* return all "user authenticated" status */
	return OK;
}

/*
 * handle an OpenID Connect Authorization Response from the OP
 */
static int oidc_handle_authorization_response(request_rec *r, oidc_cfg *c, session_rec *session) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_handle_authorization_response: entering");

	/* inialize local variables */
	char *code = NULL, *state = NULL;
	char *issuer = NULL, *original_url = NULL;

	/* by now we're pretty sure they exist */
	oidc_util_get_request_parameter(r, "code", &code);
	oidc_util_get_request_parameter(r, "state", &state);

	/* check the state parameter against what we stored in a cookie */
	if (oidc_check_state(r, state, &original_url, &issuer) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_handle_authorization_response: unable to restore state: returning HTTP 500");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* by default we'll assume that we're dealing with a single statically configured OP */
	struct oidc_provider_t *provider = &c->provider;

	/* unless a metadata directory was configured, so we'll try and get the provider settings from there */
	if (c->metadata_dir != NULL) {

		/* try and get metadata from the metadata directory for the OP that sent this response */
		if ( (oidc_metadata_get(r, c, issuer, &provider) == FALSE) || (provider == NULL) ) {

			// no luck
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_handle_authorization_response: no provider metadata found for selected OP: returning HTTP 500");
			return HTTP_INTERNAL_SERVER_ERROR;
		}
	}

	char *id_token = NULL, *access_token = NULL;
	const char*response = NULL;
	char *remoteUser = NULL;
	apr_time_t expires;
	apr_json_value_t *j_idtoken_payload = NULL;

	/* resolve the code against the token endpoint of the OP */
	if (oidc_proto_resolve_code(r, c, provider, code, &remoteUser, &j_idtoken_payload, &id_token, &access_token, &expires) == FALSE) {
		/* errors have already been reported */
		return HTTP_UNAUTHORIZED;
	}

	/* set the resolved stuff in the session */
	session->remote_user = remoteUser;
	session->expiry = expires;
	oidc_session_set(r, session, OIDC_IDTOKEN_SESSION_KEY, id_token);

	/* optionally resolve additional claims against the userinfo endpoint */
	apr_json_value_t *claims = NULL;
	if (oidc_proto_resolve_userinfo(r, c, provider, access_token, &response, &claims) == TRUE) {
		/*
		 * succesfully decoded a set claims from the response so we can store them
		 * (well actually the stringified representation in the response)
		 * in the session context safely now
		 */
		oidc_session_set(r, session, OIDC_CLAIMS_SESSION_KEY, response);
	}

	/* store the session */
	oidc_session_save(r, session);

	/* not sure whether this is required, but it won't hurt */
	r->user = remoteUser;

	/* now we've authenticated the user so go back to the URL that he originally tried to access */
	apr_table_add(r->headers_out, "Location", original_url);
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_handle_authorization_response: session created and stored, redirecting to original url: %s", original_url);
	return HTTP_MOVED_TEMPORARILY;
}

/*
 * present the user with an OP selection screen
 */
static int oidc_discovery(request_rec *r, oidc_cfg *cfg) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_discovery: entering");

	/* obtain the URL we're currently accessing, to be stored in the state/session */
	char *current_url = oidc_get_current_url(r, cfg);

	/* see if there's an external discovery page configured */
	if (cfg->discover_url != NULL) {

		/* yes, assemble the paramters for external discovery */
		char *url = apr_psprintf(r->pool, "%s%s%s=%s&%s=%s", cfg->discover_url, strchr(cfg->discover_url, '?') != NULL ? "&" : "?", OIDC_DISC_RT_PARAM, oidc_util_escape_string(r, current_url), OIDC_DISC_CB_PARAM, oidc_util_escape_string(r, cfg->redirect_uri));

		/* log what we're about to do */
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_discovery: redirecting to external discovery page: %s", url);

		/* do the actual redirect to an external discovery page */
		apr_table_add(r->headers_out, "Location", url);
		return HTTP_MOVED_TEMPORARILY;
	}

	/* get a list of all providers configured in the metadata directory */
	apr_array_header_t *arr = NULL;
	if (oidc_metadata_list(r, cfg, &arr) == FALSE)
		return oidc_util_http_sendstring(r, "mod_oidc: no configured providers found, contact your adminstrator", HTTP_UNAUTHORIZED);

	/* assemble a where-are-you-from IDP discovery HTML page */
	const char *s = "<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.1//EN" "http://www.w3.org/TR/xhtml11/DTD/xhtml11.dtd\">"
			"<html>\n"
			"	<head>\n"
			"		<meta http-equiv=\"Content-Type\" content=\"text/html;charset=UTF-8\"/>\n"
			"		<title>OpenID Connect Provider Discovery</title>\n"
			"	</head>\n"
			"	<body>\n"
			"		<center>\n"
			"			<h3>Select your OpenID Connect Identity Provider</h3>\n";

	/* list all configured providers in there */
	int i;
	for (i = 0; i < arr->nelts; i++) {
		const char *issuer = ((const char**)arr->elts)[i];
		// TODO: html escape (especially & character)

		/* point back to the redirect_uri, where the selection is handled, with an IDP selection and return_to URL */
		s = apr_psprintf(r->pool, "%s<p><a href=\"%s?%s=%s&amp;%s=%s\">%s</a></p>\n", s, cfg->redirect_uri, OIDC_DISC_OP_PARAM, oidc_util_escape_string(r, issuer), OIDC_DISC_RT_PARAM, oidc_util_escape_string(r, current_url), issuer);
	}

	s = apr_psprintf(r->pool, "%s<form method=\"get\" action=\"%s\">\n", s, cfg->redirect_uri);
	s = apr_psprintf(r->pool, "%s<input type=\"hidden\" name=\"%s\" value=\"%s\"><br>\n", s, OIDC_DISC_RT_PARAM, current_url);
	s = apr_psprintf(r->pool, "%sOr enter your account name (e.g.: \"mike@seed.gluu.org\" or \"diana@xenosmilus2.umdc.umu.se\"):<br>\n", s);
	s = apr_psprintf(r->pool, "%s<p><input type=\"text\" name=\"%s\" value=\"%s\"></p>\n", s, OIDC_DISC_ACCT_PARAM, "");
	s = apr_psprintf(r->pool, "%s<input type=\"submit\" value=\"Submit\">\n", s);
	s = apr_psprintf(r->pool, "%s</form>\n", s);

	/* footer */
	s = apr_psprintf(r->pool, "%s"
			"		</center>\n"
			"	</body>\n"
			"</html>\n", s);

	/* now send the HTML contents to the user agent */
	return oidc_util_http_sendstring(r, s, HTTP_UNAUTHORIZED);
}

/*
 * authenticate the user to the selected OP, if the OP is not selected yet, do discovery first
 */
static int oidc_authenticate_user(request_rec *r, oidc_cfg *c, oidc_provider_t *provider, const char *original_url) {

	if (provider == NULL) {

		// TODO: shouldn't we use an explicit redirect to the discovery endpoint (maybe a "discovery" param to the redirect_uri)?
		if (c->metadata_dir != NULL) return oidc_discovery(r, c);

		/* we're not using multiple OP's configured in a metadata directory, pick the statically configured OP */
		provider = &c->provider;
	}

	/* create state that restores the context when the authorization response comes in; cryptographically bind it to the browser */
	const char *state = oidc_create_state_and_set_cookie(r, original_url, provider->issuer);

	// TODO: maybe show intermediate/progress screen "redirecting to"

	/* send off to the OpenID Connect Provider */
	return oidc_proto_authorization_request(r, provider, c->redirect_uri, state, original_url);
}

/*
 * find out whether the request is a response from the IDP discovery page
 */
static apr_byte_t oidc_is_discovery_response(request_rec *r, oidc_cfg *cfg) {
	/*
	 * see if this is a call to the configured redirect_uri and
	 * the OIDC_RT_PARAM_NAME parameter is present and
	 * the OIDC_DISC_ACCT_PARAM or OIDC_DISC_OP_PARAM is present
	 */
	return ((oidc_util_request_matches_url(r, cfg->redirect_uri) == TRUE)
			&& oidc_util_request_has_parameter(r, OIDC_DISC_RT_PARAM)
			&& (oidc_util_request_has_parameter(r, OIDC_DISC_OP_PARAM)
					|| oidc_util_request_has_parameter(r, OIDC_DISC_ACCT_PARAM)));
}

/*
 * handle a response from the OP discovery page
 */
static int oidc_handle_discovery_response(request_rec *r, oidc_cfg *c) {

	/* variables to hold the values (original_url+issuer or original_url+acct) returned in the response */
	char *issuer = NULL, *original_url = NULL, *acct = NULL;
	oidc_provider_t *provider = NULL;

	oidc_util_get_request_parameter(r, OIDC_DISC_OP_PARAM, &issuer);
	oidc_util_get_request_parameter(r, OIDC_DISC_ACCT_PARAM, &acct);
	oidc_util_get_request_parameter(r, OIDC_DISC_RT_PARAM, &original_url);

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_handle_discovery_response: issuer=\"%s\", acct=\"%s\", original_url=\"%s\"", issuer, acct, original_url);

	if (acct != NULL) {

		if (oidc_proto_account_based_discovery(r, c, acct, &issuer) == FALSE) {

			/* something did not work out, show a user facing error */
			return oidc_util_http_sendstring(r, "mod_oidc: could not resolve the provided account name to an OpenID Connect provider; check your syntax", HTTP_NOT_FOUND);
		}

		/* issuer is set now, so let's continue as planned */
	}

	if (issuer != NULL) {

		/* try and get metadata from the metadata directories for the selected OP */
		if ( (oidc_metadata_get(r, c, issuer, &provider) == TRUE) && (provider != NULL) ) {

			/* now we've got a selected OP, send the user there to authenticate */
			return oidc_authenticate_user(r, c, provider, original_url);
		}

		/* something went wrong */
		return oidc_util_http_sendstring(r, "mod_oidc: could not find valid provider metadata for the specified OpenID Connect provider; contact the administrator", HTTP_NOT_FOUND);
	}

	return HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * main routine: handle OpenID Connect authentication
 */
int oidc_check_userid_openid_connect(request_rec *r, oidc_cfg *c) {

	/* first check the config required for the OpenID Connect RP role */
	if (oidc_check_config_oidc(r, c) != OK) return HTTP_INTERNAL_SERVER_ERROR;

	/* check if this is a sub-request or an initial request */
	if (ap_is_initial_req(r)) {

		/* load the session from the request state; this will be a new "empty" session if no state exists */
		session_rec *session = NULL;
		oidc_session_load(r, &session);

		/* initial request, first check if we have an existing session */
		if (session->remote_user != NULL)  {

			/* set the user in the main request for further (incl. sub-request) processing */
			r->user = (char *)session->remote_user;

			/* this is initial request and we already have a session */
			return oidc_handle_existing_session(r, c, session);

		} else if (oidc_proto_is_authorization_response(r, c)) {

			/* this is an authorization rsopnse from the OP */
			return oidc_handle_authorization_response(r, c, session);

		} else if (oidc_is_discovery_response(r, c)) {

			/* this is response from the OP discovery page */
			return oidc_handle_discovery_response(r, c);

		}
		/*
		 * else: initial request, we have no session and it is not an authorization or
		 *       discovery response: just hit the default flow for unauthenticated users
		 */
	} else {

		/* not an initial request, try to recycle what we've already established in the main request */
		if (r->main != NULL)
			r->user = r->main->user;
		else if (r->prev != NULL)
			r->user= r->prev->user;

		if (r->user != NULL) {

			/* this is a sub-request and we have a session (headers will have been scrubbed and set already) */
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_check_userid_openid_connect: recycling user '%s' from initial request for sub-request", r->user);

			return OK;
		}
		/*
		 * else: not initial request, but we could not find a session, so:
		 * just hit the default flow for unauthenticated users
		 */
	}

	/* no session (regardless of whether it is main or sub-request), go and authenticate the user */
	return oidc_authenticate_user(r, c, NULL, oidc_get_current_url(r, c));
}

/*
 * generic Apache authentication hook for this module: dispatches to OpenID Connect or OAuth 2.0 specific routines
 */
int oidc_check_user_id(request_rec *r) {

	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);

	/* log some stuff about the incoming HTTP request */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_check_user_id: incoming request: \"%s?%s\", ap_is_initial_req(r)=%d", r->parsed_uri.path, r->args, ap_is_initial_req(r));

	/* see if any authentication has been defined at all */
	if (ap_auth_type(r) == NULL)
		return DECLINED;

	/* see if we've configed OpenID Connect user authentication for this request */
	if (apr_strnatcasecmp((const char *) ap_auth_type(r), "openid-connect") == 0)
		return oidc_check_userid_openid_connect(r, c);

	/* see if we've configed OAuth 2.0 access control for this request */
	if (apr_strnatcasecmp((const char *) ap_auth_type(r), "oauth20") == 0)
		return oidc_oauth_check_userid(r, c);

	/* this is not for us but for some other handler */
	return DECLINED;
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
/*
 * generic Apache >=2.4 authorization hook for this module
 * handles both OpenID Connect or OAuth 2.0 in the same way, based on the claims stored in the session
 */
authz_status oidc_authz_checker(request_rec *r, const char *require_args, const void *parsed_require_args) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);

	/* get the set of claims from the request state (they've been set in the authentication part earlier */
	apr_json_value_t *attrs = (apr_json_value_t *)oidc_request_state_get(r, OIDC_CLAIMS_SESSION_KEY);

	/* dispatch to the >=2.4 specific authz routine */
	return oidc_authz_worker24(r, attrs, require_args);
}
#else
/*
 * generic Apache <2.4 authorization hook for this module
 * handles both OpenID Connect or OAuth 2.0 in the same way, based on the claims stored in the session
 */
int oidc_auth_checker(request_rec *r) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);

	/* get the set of claims from the request state (they've been set in the authentication part earlier */
	apr_json_value_t *attrs = (apr_json_value_t *)oidc_request_state_get(r, OIDC_CLAIMS_SESSION_KEY);

	/* get the Require statements */
	const apr_array_header_t *const reqs_arr = ap_requires(r);

	/* see if we have any */
	const require_line *const reqs = reqs_arr ? (require_line *) reqs_arr->elts : NULL;
	if (!reqs_arr) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"No require statements found, "
				"so declining to perform authorization.");
		return DECLINED;
	}

	/* dispatch to the <2.4 specific authz routine */
	return oidc_authz_worker(r, attrs, reqs, reqs_arr->nelts);
}
#endif

const command_rec oidc_config_cmds[] = {
		AP_INIT_TAKE1("OIDCProviderIssuer", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, provider.issuer), RSRC_CONF, "OpenID Connect OP issuer identifier."),
		AP_INIT_TAKE1("OIDCProviderAuthorizationEndpoint", oidc_set_url_slot, (void *)APR_OFFSETOF(oidc_cfg, provider.authorization_endpoint_url), RSRC_CONF, "Define the OpenID OP Authorization Endpoint URL (e.g.: https://localhost:9031/as/authorization.oauth2)"),
		AP_INIT_TAKE1("OIDCProviderTokenEndpoint", oidc_set_url_slot, (void *)APR_OFFSETOF(oidc_cfg, provider.token_endpoint_url), RSRC_CONF, "Define the OpenID OP Token Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
		AP_INIT_TAKE1("OIDCProviderTokenEndpointAuth", oidc_set_endpoint_auth_slot, (void *)APR_OFFSETOF(oidc_cfg, provider.token_endpoint_auth), RSRC_CONF, "Specify an authentication method for the OpenID OP Token Endpoint (e.g.: client_auth_basic)"),
		AP_INIT_TAKE1("OIDCProviderUserInfoEndpoint", oidc_set_url_slot, (void *)APR_OFFSETOF(oidc_cfg, provider.userinfo_endpoint_url), RSRC_CONF, "Define the OpenID OP UserInfo Endpoint URL (e.g.: https://localhost:9031/idp/userinfo.openid)"),

		AP_INIT_FLAG("OIDCSSLValidateServer", oidc_set_flag_slot, (void*)APR_OFFSETOF(oidc_cfg, provider.ssl_validate_server), RSRC_CONF, "Require validation of the OpenID Connect OP SSL server certificate for successful authentication (On or Off)"),
		AP_INIT_TAKE1("OIDCClientName", oidc_set_string_slot, (void *) APR_OFFSETOF(oidc_cfg, provider.client_name), RSRC_CONF, "Define the (client_name) name that the client uses for dynamic registration to the OP."),
		AP_INIT_TAKE1("OIDCClientContact", oidc_set_string_slot, (void *) APR_OFFSETOF(oidc_cfg, provider.client_contact), RSRC_CONF, "Define the contact that the client registers in dynamic registration with the OP."),
		AP_INIT_TAKE1("OIDCScope", oidc_set_string_slot, (void *) APR_OFFSETOF(oidc_cfg, provider.scope), RSRC_CONF, "Define the OpenID Connect scope that is requested from the OP."),

		AP_INIT_TAKE1("OIDCClientID", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, provider.client_id), RSRC_CONF, "Client identifier used in calls to OpenID Connect OP."),
		AP_INIT_TAKE1("OIDCClientSecret", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, provider.client_secret), RSRC_CONF, "Client secret used in calls to OpenID Connect OP."),

		AP_INIT_TAKE1("OIDCRedirectURI", oidc_set_url_slot, (void *)APR_OFFSETOF(oidc_cfg, redirect_uri), RSRC_CONF, "Define the Redirect URI (e.g.: https://localhost:9031/protected/return/uri"),
		AP_INIT_TAKE1("OIDCDiscoverURL", oidc_set_url_slot, (void *)APR_OFFSETOF(oidc_cfg, discover_url), RSRC_CONF, "Defines an external IDP Discovery page"),
		AP_INIT_TAKE1("OIDCCookieDomain", oidc_set_cookie_domain, NULL, RSRC_CONF, "Specify domain element for OIDC session cookie."),
		AP_INIT_TAKE1("OIDCCryptoPassphrase", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, crypto_passphrase), RSRC_CONF, "Passphrase used for AES crypto on cookies and state."),
		AP_INIT_TAKE1("OIDCClaimDelimiter", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, claim_delimiter), RSRC_CONF, "The delimiter to use when setting multi-valued claims in the HTTP headers."),
		AP_INIT_TAKE1("OIDCClaimPrefix ", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, claim_prefix), RSRC_CONF, "The prefix to use when setting claims in the HTTP headers."),

		AP_INIT_TAKE1("OIDCOAuthClientID", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, oauth.client_id), RSRC_CONF, "Client identifier used in calls to OAuth 2.0 Authorization server validation calls."),
		AP_INIT_TAKE1("OIDCOAuthClientSecret", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, oauth.client_secret), RSRC_CONF, "Client secret used in calls to OAuth 2.0 Authorization server validation calls."),
		AP_INIT_TAKE1("OIDCOAuthEndpoint", oidc_set_url_slot, (void *)APR_OFFSETOF(oidc_cfg, oauth.validate_endpoint_url), RSRC_CONF, "Define the OAuth AS Validation Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
		AP_INIT_TAKE1("OIDCOAuthEndpointAuth", oidc_set_endpoint_auth_slot, (void *)APR_OFFSETOF(oidc_cfg, oauth.validate_endpoint_auth), RSRC_CONF, "Specify an authentication method for the OAuth AS Validation Endpoint (e.g.: client_auth_basic)"),
		AP_INIT_FLAG("OIDCOAuthSSLValidateServer", oidc_set_flag_slot, (void*)APR_OFFSETOF(oidc_cfg, oauth.ssl_validate_server), RSRC_CONF, "Require validation of the OAuth 2.0 AS Validation Endpoint SSL server certificate for successful authentication (On or Off)"),

		AP_INIT_TAKE1("OIDCHTTPTimeoutLong", oidc_set_int_slot,  (void*)APR_OFFSETOF(oidc_cfg, http_timeout_long), RSRC_CONF, "Timeout for long duration HTTP calls (default)."),
		AP_INIT_TAKE1("OIDCHTTPTimeoutShort", oidc_set_int_slot,  (void*)APR_OFFSETOF(oidc_cfg, http_timeout_short), RSRC_CONF, "Timeout for short duration HTTP calls (registry/discovery)."),

		AP_INIT_TAKE1("OIDCCacheDir", oidc_set_dir_slot,  (void*)APR_OFFSETOF(oidc_cfg, cache_dir), RSRC_CONF, "Directory used for file-based caching."),
		AP_INIT_TAKE1("OIDCMetadataDir", oidc_set_dir_slot,  (void*)APR_OFFSETOF(oidc_cfg, metadata_dir), RSRC_CONF, "Directory that contains provider and client metadata files."),
		AP_INIT_FLAG("OIDCScrubRequestHeaders", oidc_set_flag_slot, (void *) APR_OFFSETOF(oidc_cfg, scrub_request_headers), RSRC_CONF, "Scrub user name and claim headers from the user's request."),

		AP_INIT_TAKE1("OIDCAuthNHeader", ap_set_string_slot, (void *) APR_OFFSETOF(oidc_dir_cfg, authn_header), ACCESS_CONF|OR_AUTHCFG, "Specify the HTTP header variable to set with the name of the authenticated user. By default no headers are added."),
		AP_INIT_TAKE1("OIDCCookiePath", ap_set_string_slot, (void *) APR_OFFSETOF(oidc_dir_cfg, cookie_path), ACCESS_CONF|OR_AUTHCFG, "Define the cookie path for the session cookie."),
		AP_INIT_TAKE1("OIDCCookie", ap_set_string_slot, (void *) APR_OFFSETOF(oidc_dir_cfg, cookie), ACCESS_CONF|OR_AUTHCFG, "Define the cookie name for the session cookie."),
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
