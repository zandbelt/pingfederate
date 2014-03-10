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

#ifndef MOD_OIDC_H_
#define MOD_OIDC_H_

#include <openssl/evp.h>
#include <apr_uri.h>
#include <apr_uuid.h>
#include <httpd.h>
#include <http_core.h>
#include <http_config.h>
#include <mod_auth.h>

#include "apr_json.h"

#ifndef OIDC_DEBUG
#define OIDC_DEBUG APLOG_DEBUG
#endif

/* key for storing the claims in the session context */
#define OIDC_CLAIMS_SESSION_KEY "claims"
/* key for storing the id_token in the session context */
#define OIDC_IDTOKEN_SESSION_KEY "id_token"

/* parameter name of the callback URL in the discovery response */
#define OIDC_DISC_CB_PARAM "oidc_callback"
/* parameter name of the OP provider selection in the discovery response */
#define OIDC_DISC_OP_PARAM "oidc_provider"
/* parameter name of the original URL in the discovery response */
#define OIDC_DISC_RT_PARAM "oidc_return"
/* parameter name of an account name in the discovery response */
#define OIDC_DISC_ACCT_PARAM "oidc_acct"

/* value that indicates to use cache-file based session tracking */
#define OIDC_SESSION_TYPE_22_CACHE_FILE 0
/* value that indicates to use cookie based session tracking */
#define OIDC_SESSION_TYPE_22_COOKIE 1

/* name of the cookie that binds the state in the authorization request/response to the browser */
#define OIDCStateCookieName  "oidc-state"
/* separator used to distinghuish different values in the state cookie */
#define OIDCStateCookieSep  " "

/* the (global) key for the mod_oidc related state that is stored in the request userdata context */
#define MOD_OIDC_USERDATA_KEY "mod_oidc_state"

/* use for plain GET in HTTP calls to endpoints */
#define OIDC_HTTP_GET 0
/* use for url-form-encoded HTTP POST calls to endpoints */
#define OIDC_HTTP_POST_FORM 1
/* use for JSON encoded POST calls to endpoints */
#define OIDC_HTTP_POST_JSON 2

/* for issued-at timestamp (iat) checking */
#define OIDC_IDTOKEN_IAT_SLACK 600

typedef struct oidc_provider_t {
	char *issuer;
	char *authorization_endpoint_url;
	char *token_endpoint_url;
	char *token_endpoint_auth;
	char *userinfo_endpoint_url;
	char *jwks_uri;
	char *client_id;
	char *client_secret;

	// the next ones function as global default settings too
	int ssl_validate_server;
	char *client_name;
	char *client_contact;
	char *scope;
	char *response_type;
} oidc_provider_t ;

typedef struct oidc_oauth_t {
	int ssl_validate_server;
	char *client_id;
	char *client_secret;
	char *validate_endpoint_url;
	char *validate_endpoint_auth;
} oidc_oauth_t;

typedef struct oidc_cfg {
	/* indicates whether this is a derived config, merged from a base one */
	unsigned int merged;

	/* the redirect URI as configured with the OpenID Connect OP's that we talk to */
	char *redirect_uri;
	/* (optional) external OP discovery page */
	char *discover_url;
	/* (optional) the signing algorithm the OP should use (used in dynamic client registration only) */
	char *id_token_alg;

	/* a pointer to the (single) provider that we connect to */
	/* NB: if metadata_dir is set, these settings will function as defaults for the metadata read from there) */
	oidc_provider_t provider;
	/* a pointer to the oauth server settings */
	oidc_oauth_t oauth;

	/* directory that holds the cache files (if unset, we'll try and use an OS defined one like "/tmp" */
	char *cache_dir;
	/* directory that holds the provider & client metadata files */
	char *metadata_dir;
	/* type of session management/storage */
	int session_type;

	/* tell the module to strip any mod_oidc related headers that already have been set by the user-agent, normally required for secure operation */
	int scrub_request_headers;

	int http_timeout_long;
	int http_timeout_short;
	int state_timeout;

	char *cookie_domain;
	char *claim_delimiter;
	char *claim_prefix;

	char *crypto_passphrase;

	EVP_CIPHER_CTX *encrypt_ctx;
	EVP_CIPHER_CTX *decrypt_ctx;
} oidc_cfg;

typedef struct oidc_dir_cfg {
	char *cookie_path;
	char *cookie;
	char *authn_header;
} oidc_dir_cfg;

int oidc_check_user_id(request_rec *r);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
authz_status oidc_authz_checker(request_rec *r, const char *require_args, const void *parsed_require_args);
#else
int oidc_auth_checker(request_rec *r);
#endif
void oidc_request_state_set(request_rec *r, const char *key, const char *value);
const char*oidc_request_state_get(request_rec *r, const char *key);

// oidc_oauth
int oidc_oauth_check_userid(request_rec *r, oidc_cfg *c);

// oidc_proto.c
int oidc_proto_authorization_request(request_rec *r, struct oidc_provider_t *provider, const char *redirect_uri, const char *state, const char *original_url, const char *nonce);
apr_byte_t oidc_proto_is_basic_authorization_response(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_is_implicit_post(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_is_implicit_redirect(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_resolve_code(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, char *code, const char *nonce, char **user, apr_json_value_t **j_idtoken_payload, char **s_id_token, char **s_access_token, apr_time_t *expires);
apr_byte_t oidc_proto_resolve_userinfo(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *access_token, const char **response, apr_json_value_t **claims);
apr_byte_t oidc_proto_account_based_discovery(request_rec *r, oidc_cfg *cfg, const char *acct, char **issuer);
apr_byte_t oidc_proto_parse_idtoken(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, const char *id_token, const char *nonce, char **user, apr_json_value_t **j_payload, char **s_payload, apr_time_t *expires);
int oidc_proto_javascript_implicit(request_rec *r, oidc_cfg *c);

// oidc_cache.c
apr_status_t oidc_cache_get(request_rec *r, const char *key, const char **value);
apr_status_t oidc_cache_set(request_rec *r, const char *key, const char *value, apr_time_t expiry);
const char *oidc_cache_file_path(request_rec *r, const char *key);

// oidc_authz.c
int oidc_authz_worker(request_rec *r, const apr_json_value_t *const claims, const require_line *const reqs, int nelts);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
authz_status oidc_authz_worker24(request_rec *r, const apr_json_value_t * const claims, const char *require_line);
#endif

// oidc_config.c
void *oidc_create_server_config(apr_pool_t *pool, server_rec *svr);
void *oidc_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD);
void *oidc_create_dir_config(apr_pool_t *pool, char *path);
void *oidc_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD);
void oidc_register_hooks(apr_pool_t *pool);

const char *oidc_set_flag_slot(cmd_parms *cmd, void *struct_ptr, int arg);
const char *oidc_set_int_slot(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_string_slot(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_https_slot(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_url_slot(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_endpoint_auth_slot(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_cookie_domain(cmd_parms *cmd, void *ptr, const char *value);
const char *oidc_set_dir_slot(cmd_parms *cmd, void *ptr, const char *arg);
const char *oidc_set_session_type(cmd_parms *cmd, void *ptr, const char *arg);
const char *oidc_set_response_type(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_id_token_alg(cmd_parms *cmd, void *struct_ptr, const char *arg);

char *oidc_get_cookie_path(request_rec *r);

// oidc_util.c
int oidc_strnenvcmp(const char *a, const char *b, int len);
int oidc_base64url_encode(request_rec *r, char **dst, const char *src, int src_len);
int oidc_base64url_decode(request_rec *r, char **dst, const char *src, int padding);
void oidc_set_cookie(request_rec *r, char *cookieName, char *cookieValue);
char *oidc_get_cookie(request_rec *r, char *cookieName);
int oidc_encrypt_base64url_encode_string(request_rec *r, char **dst, const char *src);
int oidc_base64url_decode_decrypt_string(request_rec *r, char **dst, const char *src);
char *oidc_get_current_url(const request_rec *r, const oidc_cfg *c);
char *oidc_url_encode(const request_rec *r, const char *str, const char *charsToEncode);
char *oidc_normalize_header_name(const request_rec *r, const char *str);

apr_byte_t oidc_util_http_call(request_rec *r, const char *url, int action, const apr_table_t *params, const char *basic_auth, const char *bearer_token, int ssl_validate_server, const char **response, int timeout);
apr_byte_t oidc_util_request_matches_url(request_rec *r, const char *url);
apr_byte_t oidc_util_request_has_parameter(request_rec *r, const char* param);
apr_byte_t oidc_util_get_request_parameter(request_rec *r, char *name, char **value);
apr_byte_t oidc_util_decode_json_and_check_error(request_rec *r, const char *str, apr_json_value_t **json);
int oidc_util_http_sendstring(request_rec *r, const char *html, int success_rvalue);
char *oidc_util_escape_string(const request_rec *r, const char *str);
char *oidc_util_unescape_string(const request_rec *r, const char *str);
apr_byte_t oidc_util_read_post(request_rec *r, apr_table_t *table);
apr_byte_t oidc_util_generate_random_base64url_encoded_value(request_rec *r, int randomLen, char **randomB64);
apr_byte_t oidc_util_file_read(request_rec *r, const char *path, char **result);

int oidc_base64url_decode_rsa_verify(request_rec *r, const char *alg, const char *signature, const char *message, const char *modulus, const char *exponent);

// oidc_crypto.c
unsigned char *oidc_crypto_aes_encrypt(request_rec *r, oidc_cfg *cfg, unsigned char *plaintext, int *len);
unsigned char *oidc_crypto_aes_decrypt(request_rec *r, oidc_cfg *cfg, unsigned char *ciphertext, int *len);
char *oidc_crypto_jwt_alg2digest(const char *alg);
apr_byte_t oidc_crypto_rsa_verify(request_rec *r, const char *alg, unsigned char* sig, int sig_len, unsigned char* msg, int msg_len, unsigned char *mod, int mod_len, unsigned char *exp, int exp_len);
apr_byte_t oidc_crypto_hmac_verify(request_rec *r, const char *alg, unsigned char* sig, int sig_len, unsigned char* msg, int msg_len, unsigned char *key, int key_len);

// oidc_metadata.c
apr_byte_t oidc_metadata_list(request_rec *r, oidc_cfg *cfg, apr_array_header_t **arr);
apr_byte_t oidc_metadata_get(request_rec *r, oidc_cfg *cfg, const char *selected, oidc_provider_t **provider);
apr_byte_t oidc_metadata_jwks_get(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, apr_json_value_t **j_jwks, apr_byte_t *refresh);

// oidc_session.c
#if MODULE_MAGIC_NUMBER_MAJOR >= 20081201
// this stuff should make it easy to migrate to the post 2.3 mod_session infrastructure
#include "mod_session.h"
#else
typedef struct {
    apr_pool_t *pool;             /* pool to be used for this session */
    apr_uuid_t *uuid;             /* anonymous uuid of this particular session */
    const char *remote_user;      /* user who owns this particular session */
    apr_table_t *entries;         /* key value pairs */
    const char *encoded;          /* the encoded version of the key value pairs */
    apr_time_t expiry;            /* if > 0, the time of expiry of this session */
    long maxage;                  /* if > 0, the maxage of the session, from
                                   * which expiry is calculated */
    int dirty;                    /* dirty flag */
    int cached;                   /* true if this session was loaded from a
                                   * cache of some kind */
    int written;                  /* true if this session has already been
                                   * written */
} session_rec;
#endif

apr_status_t oidc_session_init();
apr_status_t oidc_session_load(request_rec *r, session_rec **z);
apr_status_t oidc_session_get(request_rec *r, session_rec *z, const char *key, const char **value);
apr_status_t oidc_session_set(request_rec *r, session_rec *z, const char *key, const char *value);
apr_status_t oidc_session_save(request_rec *r, session_rec *z);

#endif /* MOD_OIDC_H_ */
