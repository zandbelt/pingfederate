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
 * @Author: Hans Zandbelt - hans.zandbelt@gmail.com
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include "mod_oidc.h"

/*
 * send an OpenID Connect authorization request to the specified provider
 */
int oidc_proto_authorization_request(request_rec *r,
		struct oidc_provider_t *provider, const char *redirect_uri,
		const char *state, const char *original_url, const char *nonce) {

	/* log some stuff */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_authorization_request: entering (issuer=%s, redirect_uri=%s, original_url=%s, state=%s, nonce=%s)",
			provider->issuer, redirect_uri, original_url, state, nonce);

	/* assemble the full URL as the authorization request to the OP where we want to redirect to */
	char *destination =
			apr_psprintf(r->pool,
					"%s%sresponse_type=%s&scope=%s&client_id=%s&state=%s&redirect_uri=%s",
					provider->authorization_endpoint_url,
					(strchr(provider->authorization_endpoint_url, '?') != NULL ?
							"&" : "?"), oidc_util_escape_string(r, provider->response_type),
							oidc_util_escape_string(r, provider->scope),
							oidc_util_escape_string(r, provider->client_id),
							oidc_util_escape_string(r, state),
							oidc_util_escape_string(r, redirect_uri));

	/*
	 * see if the chosen flow requires a nonce parameter
	 *
	 * TODO: I'd like to include the nonce in the code flow as well but Google does not allow me to do that:
	 * Error: invalid_request: Parameter not allowed for this message type: nonce
	 */
	if ( (strstr(provider->response_type, "id_token") != NULL) || (strcmp(provider->response_type, "token") == 0) ) {
		destination = apr_psprintf(r->pool, "%s&nonce=%s", destination, oidc_util_escape_string(r, nonce));
		//destination = apr_psprintf(r->pool, "%s&response_mode=fragment", destination);
	}

	/* add the redirect location header */
	apr_table_add(r->headers_out, "Location", destination);

	/* some more logging */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_authorization_request: adding outgoing header: Location: %s",
			destination);

	/* and tell Apache to return an HTTP Redirect (302) message */
	return HTTP_MOVED_TEMPORARILY;
}

/*
 * indicate whether the incoming HTTP request is an OpenID Connect Authorization Response from a Basic Client flow, syntax-wise
 */
apr_byte_t oidc_proto_is_basic_authorization_response(request_rec *r, oidc_cfg *cfg) {

	/* see if this is a call to the configured redirect_uri and the "code" and "state" parameters are present */
	return ((oidc_util_request_matches_url(r, cfg->redirect_uri) == TRUE)
			&& oidc_util_request_has_parameter(r, "code")
			&& oidc_util_request_has_parameter(r, "state"));
}

/*
 * indicate whether the incoming HTTP request is an OpenID Connect Authorization Response from an Implicit Client flow, syntax-wise
 */
apr_byte_t oidc_proto_is_implicit_post(request_rec *r, oidc_cfg *cfg) {

	/* see if this is a call to the configured redirect_uri and it is a POST */
	return ((oidc_util_request_matches_url(r, cfg->redirect_uri) == TRUE)
			&& (r->method_number == M_POST));
}

/*
 * indicate whether the incoming HTTP request is an OpenID Connect Authorization Response from an Implicit Client flow using the query parameter response type, syntax-wise
 */
apr_byte_t oidc_proto_is_implicit_redirect(request_rec *r, oidc_cfg *cfg) {

	/* see if this is a call to the configured redirect_uri and it is a POST */
	return ((oidc_util_request_matches_url(r, cfg->redirect_uri) == TRUE)
			&& (r->method_number == M_GET)
			&& oidc_util_request_has_parameter(r, "state")
			&& oidc_util_request_has_parameter(r, "id_token"));
}

/*
 * check whether the provided JSON payload (in the j_payload parameter) is a valid id_token for the specified "provider"
 */
static apr_byte_t oidc_proto_is_valid_idtoken(request_rec *r,
		oidc_provider_t *provider, apr_json_value_t *j_payload, const char *nonce,
		apr_time_t *expires) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_is_valid_idtoken: entering (looking for nonce=%s)", nonce);

	/* if a nonce is not passed, we're doing a ("code") flow where the nonce is optional */
	if (nonce != NULL) {

		/* see if we've this nonce cached already */
		const char *replay = NULL;
		oidc_cache_get(r, nonce, &replay);
		if (replay != NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_proto_is_valid_idtoken: nonce was found in cache already; replay attack!?");
			return FALSE;
		}

		apr_json_value_t *j_nonce = apr_hash_get(j_payload->value.object, "nonce",
				APR_HASH_KEY_STRING);
		if ((j_nonce == NULL) || (j_nonce->type != APR_JSON_STRING)) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_proto_is_valid_idtoken: response JSON object did not contain a \"nonce\" string");
			return FALSE;
		}
		if (strcmp(nonce, j_nonce->value.string.p) != 0) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_proto_is_valid_idtoken: the nonce value in the id_token did not match the one stored in the browser session");
			return FALSE;
		}
	}

	/* get the "issuer" value from the JSON payload */
	apr_json_value_t *iss = apr_hash_get(j_payload->value.object, "iss",
			APR_HASH_KEY_STRING);
	if ((iss == NULL) || (iss->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken: response JSON object did not contain an \"iss\" string");
		return FALSE;
	}

	/* check if the issuer matches the requested value */
	if (oidc_util_issuer_match(provider->issuer, iss->value.string.p) == FALSE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken: configured issuer (%s) does not match received \"iss\" value in id_token (%s)",
				provider->issuer, iss->value.string.p);
		return FALSE;
	}

	/* get the "exp" value from the JSON payload */
	apr_json_value_t *exp = apr_hash_get(j_payload->value.object, "exp",
			APR_HASH_KEY_STRING);
	if ((exp == NULL) || (exp->type != APR_JSON_LONG)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken: response JSON object did not contain an \"exp\" number value");
		return FALSE;
	}

	/* check if this id_token has already expired */
	if (apr_time_sec(apr_time_now()) > exp->value.lnumber) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken: id_token expired");
		return FALSE;
	}

	/* return the "exp" value in the "expires" return parameter */
	*expires = apr_time_from_sec(exp->value.lnumber);

	/* get the "iat" value from the JSON payload */
	apr_json_value_t *iat = apr_hash_get(j_payload->value.object, "iat",
			APR_HASH_KEY_STRING);
	if ((iat == NULL) || (iat->type != APR_JSON_LONG)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken: response JSON object did not contain an \"iat\" number value");
		return FALSE;
	}

	/* check if this id_token has been issued just now +- 60 seconds */
	if ((apr_time_sec(apr_time_now()) - OIDC_IDTOKEN_IAT_SLACK) > iat->value.lnumber) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken: token was issued more than 1 minute ago");
		return FALSE;
	}
	if ((apr_time_sec(apr_time_now()) + OIDC_IDTOKEN_IAT_SLACK) < iat->value.lnumber) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken: token was issued more than 1 minute in the future");
		return FALSE;
	}

	if (nonce != NULL) {
		/* cache the nonce for the window time of the token for replay prevention plus 10 seconds for safety */
		oidc_cache_set(r, nonce, nonce, apr_time_from_sec(OIDC_IDTOKEN_IAT_SLACK * 2 + 10));
	}

	/* get the "azp" value from the JSON payload, which may be NULL */
	apr_json_value_t *azp = apr_hash_get(j_payload->value.object, "azp",
			APR_HASH_KEY_STRING);
	if ((azp != NULL) && (azp->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken: id_token JSON payload contained an \"azp\" value, but it was not a string");
		return FALSE;
	}

	/*
	 * This Claim is only needed when the ID Token has a single audience value and that audience is different than the authorized party.
	 * It MAY be included even when the authorized party is the same as the sole audience.
	 */
	if ((azp != NULL)
			&& (strcmp(azp->value.string.p, provider->client_id) != 0)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"\"azp\" claim (%s) is not equal to configured client_id (%s)",
				azp->value.string.p, provider->client_id);
		return FALSE;
	}

	/* get the "aud" value from the JSON payload */
	apr_json_value_t *aud = apr_hash_get(j_payload->value.object, "aud",
			APR_HASH_KEY_STRING);

	if (aud != NULL) {

		/* check if it is a single-value */
		if (aud->type == APR_JSON_STRING) {

			/* a single-valued audience must be equal to our client_id */
			if (strcmp(aud->value.string.p, provider->client_id) != 0) {

				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						"oidc_proto_is_valid_idtoken: configured client_id (%s) did not match the JSON \"aud\" entry (%s)",
						provider->client_id, aud->value.string.p);
				return FALSE;
			}

			/* check if this is a multi-valued audience */
		} else if (aud->type == APR_JSON_ARRAY) {

			if ((aud->value.array->nelts > 1) && (azp == NULL)) {
				ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
						"oidc_proto_is_valid_idtoken: \"aud\" is an array with more than 1 element, but \"azp\" claim is not present (a SHOULD in the spec...)");
			}

			/* loop over the audience values */
			int i;
			for (i = 0; i < aud->value.array->nelts; i++) {

				apr_json_value_t *elem =
						APR_ARRAY_IDX(aud->value.array, i, apr_json_value_t *);

				/* check if it is a string, warn otherwise */
				if (elem->type != APR_JSON_STRING) {
					ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
							"oidc_proto_is_valid_idtoken: unhandled in-array JSON object type [%d]",
							elem->type);
					continue;
				}

				/* we're looking for a value in the list that matches our client id */
				if (strcmp(elem->value.string.p, provider->client_id) == 0) {
					break;
				}
			}

			/* check if we've found a match or not */
			if (i == aud->value.array->nelts) {

				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
						"oidc_proto_is_valid_idtoken: configured client_id (%s) could not be found in the JSON \"aud\" array object",
						provider->client_id);
				return FALSE;
			}

		} else {

			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_proto_is_valid_idtoken: response JSON \"aud\" object is not a string nor an array");
			return FALSE;
		}

	} else {

		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken: response JSON object did not contain an \"aud\" element");
		return FALSE;
	}

	return TRUE;
}

/*
 * check whether the provider string is a valid id_token for the specified "provider"
 */
static apr_byte_t oidc_proto_is_valid_idtoken_payload(request_rec *r,
		oidc_provider_t *provider, const char *s_idtoken_payload, const char *nonce,
		apr_json_value_t **result, apr_time_t *expires) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_is_valid_idtoken_payload: entering (%s)", s_idtoken_payload);

	/* decode the string in to a JSON structure */
	if (apr_json_decode(result, s_idtoken_payload, strlen(s_idtoken_payload),
			r->pool) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken_payload: could not decode id_token payload string in to a JSON structure");
		return FALSE;
	}

	/* a convenient helper pointer */
	apr_json_value_t *j_payload = *result;

	/* check that we've actually got a JSON object back */
	if ((j_payload == NULL) || (j_payload->type != APR_JSON_OBJECT)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_is_valid_idtoken_payload: payload from id_token did not contain a JSON object");
		return FALSE;
	}

	/* now check if the JSON is a valid id_token */
	return oidc_proto_is_valid_idtoken(r, provider, j_payload, nonce, expires);
}

/*
 * check whether the provided string is a valid id_token header
 */
static apr_byte_t oidc_proto_parse_idtoken_header(request_rec *r,
		const char *s_header, apr_json_value_t **result) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_parse_idtoken_header: entering (%s)", s_header);

	/* decode the string in to a JSON structure */
	if (apr_json_decode(result, s_header, strlen(s_header),
			r->pool) != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_parse_idtoken_header: could not decode header from id_token successfully");
		return FALSE;
	}

	/* a convenient helper pointer */
	apr_json_value_t *j_header = *result;

	/* check that we've actually got a JSON object back */
	if ((j_header == NULL) || (j_header->type != APR_JSON_OBJECT)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_parse_idtoken_header: header from id_token did not contain a JSON object");
		return FALSE;
	}

	apr_json_value_t *algorithm = apr_hash_get(j_header->value.object, "alg",
			APR_HASH_KEY_STRING);
	if ((algorithm == NULL) || (algorithm->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_parse_idtoken_header: header JSON object did not contain a \"alg\" string");
		return FALSE;
	}

	if (oidc_crypto_jwt_alg2digest(algorithm->value.string.p) == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_parse_idtoken_header: unsupported signing algorithm: %s", algorithm->value.string.p);
		return FALSE;
	}

	return TRUE;
}

/*
 * get the key from the JWKs that corresponds with the key specified in the header
 */
static apr_json_value_t *oidc_proto_get_key_from_jwks(request_rec *r, apr_json_value_t *j_header, apr_json_value_t *j_jwks) {

	const char *s_kid_match = NULL;

	apr_json_value_t *kid = apr_hash_get(j_header->value.object, "kid", APR_HASH_KEY_STRING);
	if (kid != NULL) {
		if (kid->type != APR_JSON_STRING) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_proto_get_key_from_jwks: \"kid\" is not a string");
			return NULL;;
		}
		s_kid_match = kid->value.string.p;
	}

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_proto_get_key_from_jwks: search for kid \"%s\"", s_kid_match);

	apr_json_value_t *keys = apr_hash_get(j_jwks->value.object, "keys", APR_HASH_KEY_STRING);

	int i;
	for (i = 0; i < keys->value.array->nelts; i++) {

		apr_json_value_t *elem = APR_ARRAY_IDX(keys->value.array, i, apr_json_value_t *);
		if (elem->type != APR_JSON_OBJECT) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_proto_get_key_from_jwks: \"keys\" array element is not a JSON object, skipping");
			continue;
		}
		apr_json_value_t *kty = apr_hash_get(elem->value.object, "kty", APR_HASH_KEY_STRING);
		if (strcmp(kty->value.string.p, "RSA") != 0) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_proto_get_key_from_jwks: \"keys\" array element is not an RSA key type (%s), skipping", kty->value.string.p);
			continue;
		}
		if (s_kid_match == NULL) {
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_proto_get_key_from_jwks: no kid to match, return first key found");
			return elem;
		}
		apr_json_value_t *ekid = apr_hash_get(elem->value.object, "kid", APR_HASH_KEY_STRING);
		if (ekid == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_proto_get_key_from_jwks: \"keys\" array element does not have a \"kid\" entry, skipping");
			continue;
		}
		if (strcmp(s_kid_match, ekid->value.string.p) == 0) {
			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_proto_get_key_from_jwks: found matching kid: \"%s\"", s_kid_match);
			return elem;
		}
	}

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_proto_get_key_from_jwks: return NULL");

	return NULL;
}

/*
 * get the key from the (possibly cached) set of JWKs on the jwk_uri that corresponds with the key specified in the header
 */
static apr_json_value_t * oidc_proto_get_key_from_jwk_uri(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, apr_json_value_t *j_header, apr_byte_t *refresh) {
	apr_json_value_t *j_jwks = NULL;
	apr_json_value_t *key = NULL;

	/* get the set of JSON Web Keys for this provider (possibly by downloading them from the specified provider->jwk_uri) */
	oidc_metadata_jwks_get(r, cfg, provider, &j_jwks, refresh);
	if (j_jwks == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_get_key_from_jwk_uri: could not resolve JSON Web Keys");
		return NULL;
	}

	/* get the key corresponding to the kid from the header, referencing the key that was used to sign this message */
	key = oidc_proto_get_key_from_jwks(r, j_header, j_jwks);

	/* see what we've got back */
	if ( (key == NULL) && (refresh == FALSE) ) {

		/* we did not get a key, but we have not refreshed the JWKs from the jwks_uri yet */

		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_proto_get_key_from_jwk_uri: could not find a key in the cached JSON Web Keys, doing a forced refresh");

		/* get the set of JSON Web Keys for this provider forcing a fresh download from the specified provider->jwk_uri) */
		*refresh = TRUE;
		oidc_metadata_jwks_get(r, cfg, provider, &j_jwks, refresh);
		if (j_jwks == NULL) {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
					"oidc_proto_get_key_from_jwk_uri: could not refresh JSON Web Keys");
			return NULL;
		}

		key = oidc_proto_get_key_from_jwks(r, j_header, j_jwks);

	}

	return key;
}

static apr_byte_t oidc_proto_idtoken_verify_hmac(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, apr_json_value_t *j_header, const char *signature, const char *message) {

	unsigned char *key = (unsigned char *)provider->client_secret;
	int key_len = strlen(provider->client_secret);

	unsigned char *sig = NULL;
	int sig_len = oidc_base64url_decode(r, (char **)&sig, signature, 1);

	apr_json_value_t *alg = apr_hash_get(j_header->value.object, "alg",
			APR_HASH_KEY_STRING);

	return oidc_crypto_hmac_verify(r, alg->value.string.p, sig, sig_len, (unsigned char *)message, strlen(message), key, key_len);
}

/*
 * verify the signature on an id_token
 */
static apr_byte_t oidc_proto_idtoken_verify_signature(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, apr_json_value_t *j_header, const char *signature, const char *message,  apr_byte_t *refresh) {

	/* get the key from the JWKs that corresponds with the key specified in the header */
	apr_json_value_t *key = oidc_proto_get_key_from_jwk_uri(r, cfg, provider, j_header, refresh);
	if (key == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_idtoken_verify_signature: could not find a key in the JSON Web Keys");
		if (*refresh == FALSE) {
			*refresh = TRUE;
			return oidc_proto_idtoken_verify_signature(r, cfg, provider, j_header, signature, message, refresh);
		}
		return FALSE;
	}

	/* get the modulus */
	apr_json_value_t *modulus = apr_hash_get(key->value.object, "n", APR_HASH_KEY_STRING);
	if ((modulus == NULL) || (modulus->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_idtoken_verify_signature: response JSON object did not contain a \"n\" string");
		return FALSE;
	}

	/* get the exponent */
	apr_json_value_t *exponent = apr_hash_get(key->value.object, "e", APR_HASH_KEY_STRING);
	if ((exponent == NULL) || (exponent->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_idtoken_verify_signature: response JSON object did not contain a \"e\" string");
		return FALSE;
	}

	/* do the actual signature verification */
	apr_json_value_t *algorithm = apr_hash_get(j_header->value.object, "alg",
			APR_HASH_KEY_STRING);

	if (oidc_base64url_decode_rsa_verify(r, algorithm->value.string.p, signature, message, modulus->value.string.p, exponent->value.string.p) != TRUE) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_proto_idtoken_verify_signature: signature verification on id_token failed");

		if (*refresh == FALSE) {
			*refresh = TRUE;
			return oidc_proto_idtoken_verify_signature(r, cfg, provider, j_header, signature, message, refresh);
		}
		return FALSE;
	}

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_proto_idtoken_verify_signature: signature with algorithm \"%s\" verified OK!", algorithm->value.string.p);

	/* if we've made it this far, all is OK */
	return TRUE;
}

/*
 * check whether the provided string is a valid id_token and return its parsed contents
 */
apr_byte_t oidc_proto_parse_idtoken(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *id_token, const char *nonce, char **user,
		apr_json_value_t **j_payload, char **s_payload, apr_time_t *expires) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_parse_idtoken: entering");

	/* find the header */
	const char *s = apr_pstrdup(r->pool, id_token);
	char *p = strchr(s, '.');
	if (p == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_parse_id_token: could not find first \".\" in id_token");
		return FALSE;
	}
	*p = '\0';

	/* add to the message part that is signed */
	char *header = apr_pstrdup(r->pool, s);

	/* parse the header (base64decode, json_decode) and validate it */
	char *s_header = NULL;
	oidc_base64url_decode(r, &s_header, s, 1);
	apr_json_value_t *j_header = NULL;
	if (oidc_proto_parse_idtoken_header(r, s_header, &j_header) != TRUE) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_parse_id_token: header parsing failure");
		return FALSE;
	}

	/* find the payload */
	s = ++p;
	p = strchr(s, '.');
	if (p == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_parse_id_token: could not find second \".\" in id_token");
		return FALSE;
	}
	*p = '\0';

	char *payload = apr_pstrdup(r->pool, s);

	s = ++p;

	char *signature = apr_pstrdup(r->pool, s);

	// verify signature unless we did 'code' flow and the algorithm is NONE
	// TODO: should improve "detection": in principle nonce can be used in "code" flow too
//	apr_json_value_t *algorithm = apr_hash_get(j_header->value.object, "alg", APR_HASH_KEY_STRING);
//	if ((strcmp(algorithm->value.string.p, "NONE") != 0) || (nonce != NULL)) {
//		/* verify the signature on the id_token */
//		apr_byte_t refresh = FALSE;
//		if (oidc_proto_idtoken_verify_signature(r, cfg, provider, j_header, signature, apr_pstrcat(r->pool, header, ".", payload, NULL), &refresh) == FALSE) return FALSE;
//	}

	apr_json_value_t *algorithm = apr_hash_get(j_header->value.object, "alg", APR_HASH_KEY_STRING);
	if (strncmp(algorithm->value.string.p, "HS", 2) == 0) {
		/* verify the HMAC signature on the id_token */
		if (oidc_proto_idtoken_verify_hmac(r, cfg, provider, j_header, signature, apr_pstrcat(r->pool, header, ".", payload, NULL)) == FALSE) return FALSE;
	} else {
		/* verify the RSA signature on the id_token */
		apr_byte_t refresh = FALSE;
		if (oidc_proto_idtoken_verify_signature(r, cfg, provider, j_header, signature, apr_pstrcat(r->pool, header, ".", payload, NULL), &refresh) == FALSE) return FALSE;
	}

	/* parse the payload */
	oidc_base64url_decode(r, s_payload, payload, 1);

	/* this is where the meat is */
	if (oidc_proto_is_valid_idtoken_payload(r, provider, *s_payload, nonce, j_payload,
			expires) == FALSE)
		return FALSE;

	/* extract and return the user name claim ("sub" or something similar) */
	apr_json_value_t *username = apr_hash_get((*j_payload)->value.object, "sub",
			APR_HASH_KEY_STRING);
	if ((username == NULL) || (username->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_proto_parse_id_token: response JSON object did not contain a \"sub\" string, falback to non-spec compliant (MS) \"unique_name\"");

		username = apr_hash_get((*j_payload)->value.object, "unique_name",
				APR_HASH_KEY_STRING);

		if ((username == NULL) || (username->type != APR_JSON_STRING)) {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_proto_parse_id_token: response JSON object did not contain a \"unique_name\" string either, second falback to non-spec compliant \"email\"");

			username = apr_hash_get((*j_payload)->value.object, "email",
					APR_HASH_KEY_STRING);

			if ((username == NULL) || (username->type != APR_JSON_STRING)) {
				ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
						"oidc_proto_parse_id_token: response JSON object did not contain an \"email\" string either, now fail...");

				return FALSE;
			}
		}
	}

	/* set the unique username in the session (r->user) */
	*user = apr_pstrdup(r->pool, username->value.string.p);

	/* log our results */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_parse_idtoken: valid id_token for user \"%s\" (expires in %" APR_TIME_T_FMT " seconds)",
			*user, *expires - apr_time_sec(apr_time_now()));

	/* since we've made it so far, we may as well say it is a valid id_token */
	return TRUE;
}

/*
 * resolves the code received from the OP in to an access_token and id_token and returns the parsed contents
 */
apr_byte_t oidc_proto_resolve_code(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, char *code, const char *nonce, char **user,
		apr_json_value_t **j_idtoken_payload, char **s_id_token,
		char **s_access_token, apr_time_t *expires) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_resolve_code: entering");
	const char *response = NULL;

	/* assemble the parameters for a call to the token endpoint */
	apr_table_t *params = apr_table_make(r->pool, 5);
	apr_table_addn(params, "grant_type", "authorization_code");
	apr_table_addn(params, "code", code);
	apr_table_addn(params, "redirect_uri", cfg->redirect_uri);

	/* see if we need to do basic auth or auth-through-post-params (both applied through the HTTP POST method though) */
	const char *basic_auth = NULL;
	if ((apr_strnatcmp(provider->token_endpoint_auth, "client_secret_basic"))
			== 0) {
		basic_auth = apr_psprintf(r->pool, "%s:%s", provider->client_id,
				provider->client_secret);
	} else {
		apr_table_addn(params, "client_id", provider->client_id);
		apr_table_addn(params, "client_secret", provider->client_secret);
	}
/*
	if (strcmp(provider->issuer, "https://sts.windows.net/b4ea3de6-839e-4ad1-ae78-c78e5c0cdc06/") == 0) {
		apr_table_addn(params, "resource", "https://graph.windows.net");
	}
*/
	/* resolve the code against the token endpoint */
	if (oidc_util_http_call(r, provider->token_endpoint_url,
			OIDC_HTTP_POST_FORM, params, basic_auth, NULL,
			provider->ssl_validate_server, &response,
			cfg->http_timeout_long) == FALSE) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_proto_resolve_code: could not successfully resolve the \"code\" (%s) against the token endpoint (%s)",
				code, provider->token_endpoint_url);
		return FALSE;
	}

	/* check for errors, the response itself will have been logged already */
	apr_json_value_t *result = NULL;
	if (oidc_util_decode_json_and_check_error(r, response, &result) == FALSE)
		return FALSE;

	/* get the access_token from the parsed response */
	apr_json_value_t *access_token = apr_hash_get(result->value.object,
			"access_token", APR_HASH_KEY_STRING);
	if ((access_token == NULL) || (access_token->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_resolve_code: response JSON object did not contain an access_token string");
		return FALSE;
	}

	/* log and set the obtained acces_token */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_resolve_code: returned access_token: %s",
			access_token->value.string.p);
	*s_access_token = apr_pstrdup(r->pool, access_token->value.string.p);

	/* the provider must the token type */
	apr_json_value_t *token_type = apr_hash_get(result->value.object,
			"token_type", APR_HASH_KEY_STRING);
	if ((token_type == NULL) || (token_type->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_resolve_code: response JSON object did not contain a token_type string");
		return FALSE;
	}

	/* we got the type, we only support bearer/Bearer, check that */
	if ((apr_strnatcasecmp(token_type->value.string.p, "Bearer") != 0)
			&& (provider->userinfo_endpoint_url != NULL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_resolve_code: token_type is \"%s\" and UserInfo endpoint is set: can only deal with Bearer authentication against the UserInfo endpoint!",
				token_type->value.string.p);
		return FALSE;
	}

	/* get the id_token from the response */
	apr_json_value_t *id_token = apr_hash_get(result->value.object, "id_token",
			APR_HASH_KEY_STRING);
	if ((id_token == NULL) || (id_token->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_resolve_code: response JSON object did not contain an id_token string");
		return FALSE;
	}

	/* log and set the obtained id_token */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_resolve_code: returned id_token: %s",
			id_token->value.string.p);
	*s_id_token = apr_pstrdup(r->pool, id_token->value.string.p);

	char *s_payload = NULL;

	/* parse and validate the obtained id_token and return success/failure of that */
	return oidc_proto_parse_idtoken(r, cfg, provider, id_token->value.string.p, nonce, user,
			j_idtoken_payload, &s_payload, expires);
}

/*
 * get claims from the OP UserInfo endpoint using the provided access_token
 */
apr_byte_t oidc_proto_resolve_userinfo(request_rec *r, oidc_cfg *cfg,
		oidc_provider_t *provider, const char *access_token,
		const char **response, apr_json_value_t **claims) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_resolve_userinfo: entering, endpoint=%s, access_token=%s",
			provider->userinfo_endpoint_url, access_token);

	/* only do this if an actual endpoint was set */
	if (provider->userinfo_endpoint_url == NULL)
		return FALSE;

	/* get the JSON response */
	if (oidc_util_http_call(r, provider->userinfo_endpoint_url, OIDC_HTTP_GET,
			NULL, NULL, access_token, provider->ssl_validate_server, response,
			cfg->http_timeout_long) == FALSE)
		return FALSE;

	/* decode and check for an "error" response */
	return oidc_util_decode_json_and_check_error(r, *response, claims);
}

/*
 * based on an account name, perform OpenID Connect Provider Issuer Discovery to find out the issuer and obtain and store its metadata
 */
apr_byte_t oidc_proto_account_based_discovery(request_rec *r, oidc_cfg *cfg,
		const char *acct, char **issuer) {

	// TODO: maybe show intermediate/progress screen "discovering..."

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_account_based_discovery: entering, acct=%s", acct);

	const char *resource = apr_psprintf(r->pool, "acct:%s", acct);
	const char *domain = strrchr(acct, '@');
	if (domain == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_account_based_discovery: invalid account name");
		return FALSE;
	}
	domain++;
	const char *url = apr_psprintf(r->pool, "https://%s/.well-known/webfinger",
			domain);

	apr_table_t *params = apr_table_make(r->pool, 1);
	apr_table_addn(params, "resource", resource);
	apr_table_addn(params, "rel", "http://openid.net/specs/connect/1.0/issuer");

	const char *response = NULL;
	if (oidc_util_http_call(r, url, OIDC_HTTP_GET, params, NULL, NULL,
			cfg->provider.ssl_validate_server, &response,
			cfg->http_timeout_short) == FALSE) {
		/* errors will have been logged by now */
		return FALSE;
	}

	/* decode and see if it is not an error response somehow */
	apr_json_value_t *j_response = NULL;
	if (oidc_util_decode_json_and_check_error(r, response, &j_response) == FALSE)
		return FALSE;

	/* get the links parameter */
	apr_json_value_t *j_links = apr_hash_get(j_response->value.object, "links",
			APR_HASH_KEY_STRING);
	if ((j_links == NULL) || (j_links->type != APR_JSON_ARRAY)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_account_based_discovery: response JSON object did not contain a \"links\" array");
		return FALSE;
	}

	/* get the one-and-only object in the "links" array */
	apr_json_value_t *j_object =
			((apr_json_value_t**) j_links->value.array->elts)[0];
	if ((j_object == NULL) || (j_object->type != APR_JSON_OBJECT)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_account_based_discovery: response JSON object did not contain a JSON object as the first element in the \"links\" array");
		return FALSE;
	}

	/* get the href from that object, which is the issuer value */
	apr_json_value_t *j_href = apr_hash_get(j_object->value.object, "href",
			APR_HASH_KEY_STRING);
	if ((j_href == NULL) || (j_href->type != APR_JSON_STRING)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r,
				"oidc_proto_account_based_discovery: response JSON object did not contain a \"href\" element in the first \"links\" array object");
		return FALSE;
	}

	*issuer = (char *) j_href->value.string.p;

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			"oidc_proto_account_based_discovery: returning issuer \"%s\" for account \"%s\" after doing succesful webfinger-based discovery",
			*issuer, acct);

	return TRUE;
}

int oidc_proto_javascript_implicit(request_rec *r, oidc_cfg *c) {

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_proto_javascript_implicit: entering");

//	char *java_script = NULL;
//	if (oidc_util_file_read(r, "/Users/hzandbelt/eclipse-workspace/mod_oidc/src/implicit_post.html", &java_script) == FALSE) return HTTP_INTERNAL_SERVER_ERROR;

	const char *java_script =
		"<!DOCTYPE html PUBLIC \"-//W3C//DTD XHTML 1.0 Strict//EN\" \"http://www.w3.org/TR/xhtml1/DTD/xhtml1-strict.dtd\">\n"
		"<html xmlns=\"http://www.w3.org/1999/xhtml\" lang=\"en\" xml:lang=\"en\">\n"
		"  <head>\n"
		"    <meta http-equiv=\"Content-Type\" content=\"text/html; charset=utf-8\"/>\n"
		"    <script type=\"text/javascript\">\n"
		"      function postOnLoad() {\n"
		"        var params = {}\n"
		"        encoded = location.hash.substring(1).split(\"&\");\n"
		"        for (i = 0; i < encoded.length; i++) {\n"
		"          encoded[i].replace(/\\+/g, \" \");\n"
		"          var n = encoded[i].indexOf(\"=\");\n"
		"          var input = document.createElement(\"input\");\n"
		"          input.type = \"hidden\";\n"
		"          input.name = decodeURIComponent(encoded[i].substring(0, n));\n"
		"          input.value = decodeURIComponent(encoded[i].substring(n+1));\n"
		"          document.forms[0].appendChild(input);\n"
		"        }\n"
		"        document.forms[0].action = window.location.href.substr(0, window.location.href.indexOf('#'));\n"
		"        document.forms[0].submit();\n"
		"      }\n"
		"    </script>\n"
		"    <title>Submitting...</title>\n"
		"  </head>\n"
		"  <body onload=\"postOnLoad()\">\n"
		"    <p>Submitting...</p>\n"
		"    <form method=\"post\"/>\n"
		"  </body>\n"
		"</html>\n";

	/*
	 * need to put in an error code to terminate sub-request processing... (which OK would allow)
	 * TODO: is this really unavoidable?
	 * I'm not sure that every browser will interpret a 302 without a location header and HTML/Javascript
	 * content in the way that we want here...
	 */
	//return oidc_util_http_sendstring(r, apr_psprintf(r->pool, java_script, c->redirect_uri), OK);
	//return oidc_util_http_sendstring(r, apr_psprintf(r->pool, java_script, c->redirect_uri), HTTP_MOVED_TEMPORARILY);
	return oidc_util_http_sendstring(r, java_script, HTTP_MOVED_TEMPORARILY);
}

