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

typedef struct oidc_provider_t {
	int ssl_validate_server;
	char *issuer;
	char *authorization_endpoint_url;
	char *token_endpoint_url;
	char *token_endpoint_auth;
	char *userinfo_endpoint_url;
	char *client_id;
	char *client_secret;
	char *scope;
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

	/* a pointer to the (single) provider that we connect to */
	/* NB: if metadata_dir is set, these settings will function as defaults for the metadata read from there) */
	oidc_provider_t provider;
	/* a pointer to the oauth server settings */
	oidc_oauth_t oauth;

	/* directory that holds the cache files (if unset, we'll try and use an OS defined one like "/tmp" */
	char *cache_dir;
	/* directory that holds the provider & client metadata files */
	char *metadata_dir;

	/* tell the module to strip any mod_oidc related headers that already have been set by the user-agent, normally required for secure operation */
	int scrub_request_headers;

	char *cookie_domain;
	char *claim_delimiter;
	char *claim_prefix;

	char *crypto_passphrase;
	EVP_CIPHER_CTX e_ctx;
	EVP_CIPHER_CTX d_ctx;
} oidc_cfg;

typedef struct oidc_dir_cfg {
	char *dir_scope;
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

// oidc_proto.c
int oidc_proto_authorization_request(request_rec *r, struct oidc_provider_t *provider, const char *redirect_uri, const char *state, const char *original_url);
apr_byte_t oidc_proto_is_authorization_response(request_rec *r, oidc_cfg *cfg);
apr_byte_t oidc_proto_resolve_code(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, char *code, char **user, apr_json_value_t **j_idtoken_payload, char **s_id_token, char **s_access_token, apr_time_t *expires);
apr_byte_t oidc_proto_resolve_userinfo(request_rec *r, oidc_cfg *cfg, oidc_provider_t *provider, char **response, char *access_token);

// oidc_cache.c
apr_status_t oidc_cache_get(request_rec *r, const char *key, const char **value);
apr_status_t oidc_cache_set(request_rec *r, const char *key, const char *value, apr_time_t expiry);

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
const char *oidc_set_string_slot(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_crypto_passphrase(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_url_slot(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_endpoint_auth_slot(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_cookie_domain(cmd_parms *cmd, void *ptr, const char *value);
const char *oidc_set_dir_slot(cmd_parms *cmd, void *ptr, const char *arg);

char *oidc_get_endpoint(request_rec *r, apr_uri_t *url, const char *s);
char *oidc_get_dir_scope(request_rec *r);

// oidc_util.c
int oidc_strnenvcmp(const char *a, const char *b, int len);
int oidc_base64url_decode(request_rec *r, char **dst, const char *src, int padding);
char *oidc_escape_string(const request_rec *r, const char *str);
char *oidc_http_call(request_rec *r, const char *url, const char *postfields, const char *basic_auth, const char *bearer_token, int ssl_validate_server);
void oidc_set_cookie(request_rec *r, char *cookieName, char *cookieValue);
char *oidc_get_cookie(request_rec *r, char *cookieName);
int oidc_encrypt_base64url_encode_string(request_rec *r, char **dst, const char *src);
int oidc_base64url_decode_decrypt_string(request_rec *r, char **dst, const char *src);
char *oidc_get_current_url(const request_rec *r, const oidc_cfg *c);
char *oidc_url_encode(const request_rec *r, const char *str, const char *charsToEncode);
char *oidc_normalize_header_name(const request_rec *r, const char *str);
apr_byte_t oidc_request_matches_url(request_rec *r, const char *url);
apr_byte_t oidc_request_has_parameter(request_rec *r, const char* param);
apr_byte_t oidc_get_request_parameter(request_rec *r, char *name, char **value);

// oidc_crypto.c
apr_status_t oidc_crypto_init(oidc_cfg *cfg, server_rec *s);
unsigned char *oidc_crypto_aes_encrypt(request_rec *r, EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
unsigned char *oidc_crypto_aes_decrypt(request_rec *r, EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);

// oidc_metadata.c
apr_status_t oidc_metadata_dir_check(apr_pool_t *pool, server_rec *s, const char *path);
apr_status_t oidc_metadata_list(request_rec *r, oidc_cfg *cfg, apr_array_header_t **arr);
apr_status_t oidc_metadata_get(request_rec *r, oidc_cfg *cfg, const char *selected, oidc_provider_t **provider);

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
