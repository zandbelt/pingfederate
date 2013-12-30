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

#include "apr_json.h"

#define OIDC_DEBUG APLOG_INFO
//#define APLOG_OIDC_DEBUG APLOG_DEBUG

typedef struct oidc_cfg {
	unsigned int merged;
	int ssl_validate_server;
	char *client_id;
	char *client_secret;
	apr_uri_t redirect_uri;
	char *issuer;
	apr_uri_t authorization_endpoint_url;
	apr_uri_t token_endpoint_url;
	char *token_endpoint_auth;
	apr_uri_t userinfo_endpoint_url;
	char *cookie_domain;
	char *crypto_passphrase;
	char *attribute_delimiter;
	char *attribute_prefix;
	char *scope;
	char *validate_client_id;
	char *validate_client_secret;
	EVP_CIPHER_CTX e_ctx;
	EVP_CIPHER_CTX d_ctx;
} oidc_cfg;

typedef struct oidc_dir_cfg {
	char *dir_scope;
	char *cookie;
	char *authn_header;
	char *scrub_request_headers;
} oidc_dir_cfg;

int oidc_auth_checker(request_rec *r);
int oidc_check_user_id(request_rec *r);

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
authz_status oidc_authz_checker(request_rec *r, const char *require_line);
#endif

void oidc_request_state_set(request_rec *r, const char *key, const char *value);
const char*oidc_request_state_get(request_rec *r, const char *key);

// oidc_cache.c
apr_status_t oidc_cache_get(request_rec *r, const char *key, const char **value);
apr_status_t oidc_cache_set(request_rec *r, const char *key, const char *value, apr_time_t expiry);

// oidc_authz.c
int oidc_authz_worker(request_rec *r, const apr_json_value_t *const attrs, const require_line *const reqs, int nelts);

// oidc_config.c
void *oidc_create_server_config(apr_pool_t *pool, server_rec *svr);
void *oidc_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD);
void *oidc_create_dir_config(apr_pool_t *pool, char *path);
void *oidc_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD);
void oidc_register_hooks(apr_pool_t *pool);

const char *oidc_set_flag_slot(cmd_parms *cmd, void *struct_ptr, int arg);
const char *oidc_set_string_slot(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_uri_slot(cmd_parms *cmd, void *struct_ptr, const char *arg);
const char *oidc_set_token_endpoint_auth(cmd_parms *cmd, void *ptr, const char *value);
const char *oidc_set_cookie_domain(cmd_parms *cmd, void *ptr, const char *value);

char *oidc_get_endpoint(request_rec *r, apr_uri_t *url, const char *s);
char *oidc_get_dir_scope(request_rec *r);

// oidc_util.c
int oidc_strnenvcmp(const char *a, const char *b, int len);
int oidc_base64url_decode(request_rec *r, char **dst, const char *src, int padding);
char *oidc_escape_string(const request_rec *r, const char *str);
char *oidc_http_call(request_rec *r, oidc_cfg *c, const char *url, const char *postfields, const char *basic_auth, const char *bearer_token);
void oidc_set_cookie(request_rec *r, char *cookieName, char *cookieValue);
char *oidc_get_cookie(request_rec *r, char *cookieName);
int oidc_encrypt_base64url_encode_string(request_rec *r, char **dst, const char *src);
int oidc_base64url_decode_decrypt_string(request_rec *r, char **dst, const char *src);
char *oidc_get_current_url(const request_rec *r, const oidc_cfg *c);
char *oidc_url_encode(const request_rec *r, const char *str, const char *charsToEncode);
char *oidc_normalize_header_name(const request_rec *r, const char *str);

// oidc_crypto.c
const char *oidc_crypto_aes_init(const char *passphrase, EVP_CIPHER_CTX *encode, EVP_CIPHER_CTX *decode);
unsigned char *oidc_crypto_aes_encrypt(apr_pool_t *pool, EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len);
unsigned char *oidc_crypto_aes_decrypt(apr_pool_t *pool, EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len);

// oidc_session.c
#if MODULE_MAGIC_NUMBER_MAJOR >= 20081201
#define OIDC_SESSION_USE_APACHE_SESSIONS 1
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
