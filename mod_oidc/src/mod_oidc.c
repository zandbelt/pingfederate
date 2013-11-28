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
 * Apache hosted content through an external OpenID Connect Provider.
 * 
 * Version 1.1 - sets the REMOTE_USER variable to the id_token sub claim, other claims are
 * passed in HTTP headers with configurable prefix.
 * 
 * Todo for version 1.2: allow for authorization rules (based on Requires primitive) that
 * can do matching against the set of claims provided in the id_token.
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
 * LogLevel debug
 *
 * OIDCClientID <your-client-id-administered-through-the-google-api-console>
 * OIDCClientSecret <your-client-secret-administered-through-the-google-api-console>
 * OIDCIssuer accounts.google.com
 * OIDCAuthorizationEndpoint https://accounts.google.com/o/oauth2/auth?hd=<your-domain>&approval_prompt=force
 * OIDCRedirectURI https://localhost/example
 * OIDCTokenEndpoint https://accounts.google.com/o/oauth2/token
 * OIDCCryptoPassphrase <some-generated-password>
 * OIDCScope "openid email profile"
 *
 * <Location /example>
 *    Authtype openid-connect
 *    require valid-user
 * </Location>
 * ==========================================================
 *
 **************************************************************************/

#include <stdio.h>

#include <curl/curl.h>
#include <openssl/evp.h>
#include <openssl/aes.h>

#include "apr_hash.h"
#include "apr_strings.h"
#include "ap_config.h"
#include "ap_provider.h"
#include "apr_lib.h"
#include "apr_file_io.h"
#include "util_md5.h"
#include "apr_md5.h"
#include "apr_base64.h"

#include "httpd.h"
#include "http_core.h"
#include "http_config.h"
#include "http_log.h"
#include "http_protocol.h"
#include "http_request.h"

#include "apr_json.h"

#define OIDC_DEFAULT_SSL_VALIDATE_SERVER 1
#define OIDC_DEFAULT_CLIENT_ID NULL
#define OIDC_DEFAULT_CLIENT_SECRET NULL
#define OIDC_DEFAULT_REDIRECT_URI NULL
#define OIDC_DEFAULT_AUTHORIZATION_ENDPOINT NULL
#define OIDC_DEFAULT_TOKEN_ENDPOINT NULL
#define OIDC_DEFAULT_COOKIE "MOD_OIDC"
#define OIDC_DEFAULT_AUTHN_HEADER NULL
#define OIDC_DEFAULT_SCRUB_REQUEST_HEADERS NULL
#define OIDC_DEFAULT_DIR_SCOPE NULL
#define OIDC_DEFAULT_COOKIE_DOMAIN NULL
#define OIDC_DEFAULT_CRYPTO_PASSPHRASE NULL
#define OIDC_DEFAULT_ISSUER NULL
#define OIDC_DEFAULT_ATTRIBUTE_DELIMITER ","
#define OIDC_DEFAULT_ATTRIBUTE_PREFIX "OIDC_ATTR_"
#define OIDC_DEFAULT_SCOPE "openid"

module AP_MODULE_DECLARE_DATA oidc_module;

typedef struct oidc_cfg {
	unsigned int merged;
	int ssl_validate_server;
	char *client_id;
	char *client_secret;
	apr_uri_t redirect_uri;
	char *issuer;
	apr_uri_t authorization_endpoint_url;
	apr_uri_t token_endpoint_url;
	char *cookie_domain;
	char *crypto_passphrase;
	char *attribute_delimiter;
	char *attribute_prefix;
	char *scope;
	EVP_CIPHER_CTX e_ctx;
	EVP_CIPHER_CTX d_ctx;
} oidc_cfg;

typedef struct oidc_dir_cfg {
	char *dir_scope;
	char *cookie;
	char *authn_header;
	char *scrub_request_headers;
} oidc_dir_cfg;

int oidc_aes_init(server_rec *s) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config, &oidc_module);

	if (cfg->crypto_passphrase == NULL) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "MOD_OIDC: OIDCCryptoPassphrase has not been set; can't continue initializing crypto!");
		return -1;
	}

	unsigned char *key_data = (unsigned char *)cfg->crypto_passphrase;
	int key_data_len = strlen(cfg->crypto_passphrase);

	unsigned int s_salt[] = {41892, 72930};
	unsigned char *salt = (unsigned char *)&s_salt;

	int i, nrounds = 5;
	unsigned char key[32], iv[32];

	/*
	 * Gen key & IV for AES 256 CBC mode. A SHA1 digest is used to hash the supplied key material.
	 * nrounds is the number of times the we hash the material. More rounds are more secure but
	 * slower.
	 */
	i = EVP_BytesToKey(EVP_aes_256_cbc(), EVP_sha1(), salt, key_data, key_data_len, nrounds, key, iv);
	if (i != 32) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "MOD_OIDC: Key size is %d bits - should be 256 bits!", i);
		return -1;
	}

	EVP_CIPHER_CTX_init(&cfg->e_ctx);
	EVP_EncryptInit_ex(&cfg->e_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	EVP_CIPHER_CTX_init(&cfg->d_ctx);
	EVP_DecryptInit_ex(&cfg->d_ctx, EVP_aes_256_cbc(), NULL, key, iv);

	return 0;
}

unsigned char *oidc_aes_encrypt(apr_pool_t *pool, EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len) {
	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = apr_palloc(pool, c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL);

	/* update ciphertext, c_len is filled with the length of ciphertext generated,
	 *len is the size of plaintext in bytes */
	EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len);

	/* update ciphertext with the final remaining bytes */
	EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len);

	*len = c_len + f_len;
	return ciphertext;
}

unsigned char *oidc_aes_decrypt(request_rec *r, EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len) {
	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = apr_palloc(r->pool, p_len + AES_BLOCK_SIZE);

	if (!EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_OIDC: EVP_DecryptInit_ex failed!");
		return NULL;
	}
	if (!EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_OIDC: EVP_DecryptUpdate failed!");
		return NULL;
	}
	if (!EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_OIDC: EVP_DecryptFinal_ex failed!");
		return NULL;
	}

	*len = p_len + f_len;
	return plaintext;
}

// TODO: always padded now, do we need an option to remove the padding?
int oidc_base64url_encode(request_rec *r, char **dst, const char *src, int src_len) {
	int enc_len = apr_base64_encode_len(src_len);
	char *enc = apr_palloc(r->pool, enc_len);
	apr_base64_encode(enc, (const char *)src, src_len);
	int i = 0;
	while (enc[i] != '\0') {
		if (enc[i] == '+') enc[i] = '-';
		if (enc[i] == '/') enc[i] = '_';
		if (enc[i] == '=') enc[i] = ',';
		i++;
	}
	*dst = enc;
	return enc_len;
}

// TODO: check base64url decoding/encoding code...
int oidc_base64url_decode(request_rec *r, char **dst, const char *src, int padding) {
	char *dec = apr_pstrdup(r->pool, src);
	int i = 0;
	while (dec[i] != '\0') {
		if (dec[i] == '-') dec[i] = '+';
		if (dec[i] == '_') dec[i] = '/';
		if (dec[i] == ',') dec[i] = '=';
		i++;
	}
	if (padding == 1) {
		switch (strlen(dec) % 4) {
			case 0:
				break;
			case 2:
				dec = apr_pstrcat(r->pool, dec, "==", NULL);
				break;
			case 3:
				dec = apr_pstrcat(r->pool, dec, "=", NULL);
				break;
			default:
				return 0;
		}
	}
	int dlen = apr_base64_decode_len(dec);
	*dst = apr_palloc(r->pool, dlen);
	return apr_base64_decode(*dst, dec);
}

int oidc_encrypt_base64url_encode_string(request_rec *r, char **dst, const char *src) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);
	int crypted_len = strlen(src) + 1;
	unsigned char *crypted = oidc_aes_encrypt(r->pool, &c->e_ctx, (unsigned char *)src, &crypted_len);
	return oidc_base64url_encode(r, dst, (const char *)crypted, crypted_len);
}

int oidc_base64url_decode_decrypt_string(request_rec *r, char **dst, const char *src) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);
	char *decbuf = NULL;
	int dec_len = oidc_base64url_decode(r, &decbuf, src, 0);
	*dst = (char *)oidc_aes_decrypt(r, &c->d_ctx, (unsigned char *)decbuf, &dec_len);
	return dec_len;
}

const char *oidc_set_flag_slot(cmd_parms *cmd, void *struct_ptr, int arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(cmd->server->module_config, &oidc_module);
    return ap_set_flag_slot(cmd, cfg, arg);
}

const char *oidc_set_string_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(cmd->server->module_config, &oidc_module);
	return ap_set_string_slot(cmd, cfg, arg);
}

const char *oidc_set_url(apr_pool_t *pool, apr_uri_t *uri, const char *url) {
	if (url == NULL) {
		memset(uri, '\0', sizeof(apr_uri_t));
		return NULL;
	}
	if (apr_uri_parse(pool, url, uri) != APR_SUCCESS) {
		return apr_psprintf(pool, "MOD_OIDC: URL '%s' could not be parsed!", url);
	}
	if (uri->port == 0) uri->port = apr_uri_port_of_scheme(uri->scheme);
	if (uri->hostname == NULL) return apr_psprintf(pool, "MOD_OIDC: hostname in URL '%s' parsed to NULL!", url);
	return NULL;
}

const char *oidc_set_uri_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(cmd->server->module_config, &oidc_module);
	int offset = (int)(long)cmd->info;
	apr_uri_t *p = (apr_uri_t *)((unsigned char *)cfg + offset);
	return oidc_set_url(cmd->pool, p, arg);
}

const char *oidc_set_cookie_domain(cmd_parms *cmd, void *ptr, const char *value) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(cmd->server->module_config, &oidc_module);
	size_t sz, limit;
	char d;
	limit = strlen(value);
	for(sz = 0; sz < limit; sz++) {
		d = value[sz];
		if( (d < '0' || d > '9') &&
				(d < 'a' || d > 'z') &&
				(d < 'A' || d > 'Z') &&
				d != '.' && d != '-') {
			return(apr_psprintf(cmd->pool, "MOD_OIDC: Invalid character (%c) in OIDCCookieDomain", d));
		}
	}
	cfg->cookie_domain = apr_pstrdup(cmd->pool, value);
	return NULL;
}

void *oidc_create_server_config(apr_pool_t *pool, server_rec *svr) {
	oidc_cfg *c = apr_pcalloc(pool, sizeof(oidc_cfg));
	c->merged = FALSE;
	c->ssl_validate_server = OIDC_DEFAULT_SSL_VALIDATE_SERVER;
	c->client_id = OIDC_DEFAULT_CLIENT_ID;
	c->client_secret = OIDC_DEFAULT_CLIENT_SECRET;
	c->cookie_domain = OIDC_DEFAULT_COOKIE_DOMAIN;
	c->crypto_passphrase = OIDC_DEFAULT_CRYPTO_PASSPHRASE;
	c->issuer = OIDC_DEFAULT_ISSUER;
	oidc_set_url(pool, &c->authorization_endpoint_url, OIDC_DEFAULT_AUTHORIZATION_ENDPOINT);
	oidc_set_url(pool, &c->token_endpoint_url, OIDC_DEFAULT_TOKEN_ENDPOINT);
	oidc_set_url(pool, &c->redirect_uri, OIDC_DEFAULT_REDIRECT_URI);
	c->attribute_delimiter = OIDC_DEFAULT_ATTRIBUTE_DELIMITER;
	c->attribute_prefix = OIDC_DEFAULT_ATTRIBUTE_PREFIX;
	c->scope = OIDC_DEFAULT_SCOPE;
	return c;
}

void *oidc_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD) {
	oidc_cfg *c = apr_pcalloc(pool, sizeof(oidc_cfg));
	oidc_cfg *base = BASE;
	oidc_cfg *add = ADD;
	apr_uri_t test;
	memset(&test, '\0', sizeof(apr_uri_t));
	c->merged = TRUE;
	c->ssl_validate_server = (add->ssl_validate_server != OIDC_DEFAULT_SSL_VALIDATE_SERVER ? add->ssl_validate_server : base->ssl_validate_server);
	c->client_id = (apr_strnatcasecmp(add->client_id, OIDC_DEFAULT_CLIENT_ID) != 0 ? add->client_id : base->client_id);
	c->client_secret = (apr_strnatcasecmp(add->client_secret, OIDC_DEFAULT_CLIENT_SECRET) != 0 ? add->client_secret : base->client_secret);
	c->crypto_passphrase = (apr_strnatcasecmp(add->crypto_passphrase, OIDC_DEFAULT_CRYPTO_PASSPHRASE) != 0 ? add->crypto_passphrase : base->crypto_passphrase);
	c->issuer = (apr_strnatcasecmp(add->issuer, OIDC_DEFAULT_ISSUER) != 0 ? add->issuer : base->issuer);
	if(memcmp(&add->authorization_endpoint_url, &test, sizeof(apr_uri_t)) == 0)
		memcpy(&c->authorization_endpoint_url, &base->authorization_endpoint_url, sizeof(apr_uri_t));
	else
		memcpy(&c->authorization_endpoint_url, &add->authorization_endpoint_url, sizeof(apr_uri_t));
	if(memcmp(&add->token_endpoint_url, &test, sizeof(apr_uri_t)) == 0)
		memcpy(&c->token_endpoint_url, &base->token_endpoint_url, sizeof(apr_uri_t));
	else
		memcpy(&c->token_endpoint_url, &add->token_endpoint_url, sizeof(apr_uri_t));
	if(memcmp(&add->redirect_uri, &test, sizeof(apr_uri_t)) == 0)
		memcpy(&c->redirect_uri, &base->redirect_uri, sizeof(apr_uri_t));
	else
		memcpy(&c->redirect_uri, &add->redirect_uri, sizeof(apr_uri_t));
	c->cookie_domain = (add->cookie_domain != OIDC_DEFAULT_COOKIE_DOMAIN ? add->cookie_domain : base->cookie_domain);
	c->attribute_delimiter = (apr_strnatcasecmp(add->attribute_delimiter, OIDC_DEFAULT_ATTRIBUTE_DELIMITER) != 0 ? add->attribute_delimiter : base->attribute_delimiter);
	c->attribute_prefix = (apr_strnatcasecmp(add->attribute_prefix, OIDC_DEFAULT_ATTRIBUTE_PREFIX) != 0 ? add->attribute_prefix : base->attribute_prefix);
	c->scope = (apr_strnatcasecmp(add->scope, OIDC_DEFAULT_SCOPE) != 0 ? add->scope : base->scope);
	return c;
}

void *oidc_create_dir_config(apr_pool_t *pool, char *path) {
	oidc_dir_cfg *c = apr_pcalloc(pool, sizeof(oidc_dir_cfg));
	c->cookie = OIDC_DEFAULT_COOKIE;
	c->dir_scope = OIDC_DEFAULT_DIR_SCOPE;
	c->authn_header = OIDC_DEFAULT_AUTHN_HEADER;
	c->scrub_request_headers = OIDC_DEFAULT_SCRUB_REQUEST_HEADERS;
	return(c);
}

void *oidc_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD) {
	oidc_dir_cfg *c = apr_pcalloc(pool, sizeof(oidc_dir_cfg));
	oidc_dir_cfg *base = BASE;
	oidc_dir_cfg *add = ADD;
	c->cookie = (apr_strnatcasecmp(add->cookie, OIDC_DEFAULT_COOKIE) != 0 ?
		add->cookie : base->cookie);
	c->dir_scope = (add->dir_scope != OIDC_DEFAULT_DIR_SCOPE ?
		add->dir_scope : base->dir_scope);
	if(add->dir_scope != NULL && apr_strnatcasecmp(add->dir_scope, "Off") == 0)
		c->dir_scope = NULL;
	c->authn_header = (add->authn_header != OIDC_DEFAULT_AUTHN_HEADER ?
		add->authn_header : base->authn_header);
	if (add->authn_header != NULL && apr_strnatcasecmp(add->authn_header, "Off") == 0)
		c->authn_header = NULL;
	c->scrub_request_headers = (add->scrub_request_headers != OIDC_DEFAULT_SCRUB_REQUEST_HEADERS ?
		 add->scrub_request_headers :
		 base->scrub_request_headers);
	if(add->scrub_request_headers != NULL && apr_strnatcasecmp(add->scrub_request_headers, "Off") == 0)
		c->scrub_request_headers = NULL;
	return(c);
}

int oidc_char_to_env(int c) {
	return apr_isalnum(c) ? apr_toupper(c) : '_';
}

/* Compare two strings based on how they would be converted to an
 * environment variable, as per oidc_char_to_env. If len is specified
 * as less than zero, then the full strings will be compared. Returns
 * less than, equal to, or greater than zero based on whether the
 * first argument's conversion to an environment variable is less
 * than, equal to, or greater than the second. */
int oidc_strnenvcmp(const char *a, const char *b, int len) {
	int d, i = 0;
	while (1) {
		/* If len < 0 then we don't stop based on length */
		if (len >= 0 && i >= len) return 0;

		/* If we're at the end of both strings, they're equal */
		if (!*a && !*b) return 0;

		/* If the second string is shorter, pick it: */
		if (*a && !*b) return 1;

		/* If the first string is shorter, pick it: */
		if (!*a && *b) return -1;

		/* Normalize the characters as for conversion to an
		 * environment variable. */
		d = oidc_char_to_env(*a) - oidc_char_to_env(*b);
		if (d) return d;

		a++;
		b++;
		i++;
	}
	return 0;
}

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

void oidc_get_code_and_state(request_rec *r, char **code, char **state) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_get_code_and_state()");

	// TODO: check that the request path matches the configured redirect URI
	// (currently a regular URL can't have a code= parameter without it being interpreted as an OIDC callback)
	char *tokenizer_ctx, *p, *args, *rv = NULL;
	const char *k_code_param = "code=";
	const size_t k_code_param_sz = strlen(k_code_param);
	const char *k_state_param = "state=";
	const size_t k_state_param_sz = strlen(k_state_param);

	if (r->args == NULL || strlen(r->args) == 0) return;

	args = apr_pstrndup(r->pool, r->args, strlen(r->args));

	p = apr_strtok(args, "&", &tokenizer_ctx);
	do {
		if (p && strncmp(p, k_code_param, k_code_param_sz) == 0) {
			*code = apr_pstrdup(r->pool, p + k_code_param_sz);
			ap_unescape_url(*code);
		}
		if (p && strncmp(p, k_state_param, k_state_param_sz) == 0) {
			oidc_base64url_decode_decrypt_string(r, state, p + k_state_param_sz);
		}
		p = apr_strtok(NULL, "&", &tokenizer_ctx);
	} while (p);
}

char *oidc_get_cookie(request_rec *r, char *cookieName) {
	char *cookie, *tokenizerCtx, *rv = NULL;
	apr_byte_t cookieFound = FALSE;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_get_cookie()");

	char *cookies = apr_pstrdup(r->pool, (char *) apr_table_get(r->headers_in, "Cookie"));
	if(cookies != NULL) {
		/* tokenize on ; to find the cookie we want */
		cookie = apr_strtok(cookies, ";", &tokenizerCtx);
		do {
			while (cookie != NULL && *cookie == ' ')
				cookie++;
			if(strncmp(cookie, cookieName, strlen(cookieName)) == 0) {
				cookieFound = TRUE;
				/* skip to the meat of the parameter (the value after the '=') */
				cookie += (strlen(cookieName)+1);
				rv = apr_pstrdup(r->pool, cookie);
			}
			cookie = apr_strtok(NULL, ";", &tokenizerCtx);
		/* no more parameters */
		if(cookie == NULL)
			break;
		} while (cookieFound == FALSE);
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "oidc_get_cookie: returning %s", rv);

	return rv;
}

#define OIDC_CURL_MAX_RESPONSE_SIZE 65536

typedef struct oidc_curl_buffer {
	char buf[OIDC_CURL_MAX_RESPONSE_SIZE];
	size_t written;
} oidc_curl_buffer;

size_t oidc_curl_write(const void *ptr, size_t size, size_t nmemb, void *stream) {
	oidc_curl_buffer *curlBuffer = (oidc_curl_buffer *) stream;

	if((nmemb*size) + curlBuffer->written >= OIDC_CURL_MAX_RESPONSE_SIZE)
		return 0;

	memcpy((curlBuffer->buf + curlBuffer->written), ptr, (nmemb*size));
	curlBuffer->written += (nmemb*size);

	return (nmemb*size);
}

char *oidc_url_encode(const request_rec *r, const char *str,
								const char *charsToEncode) {
	char *rv, *p;
	const char *q;
	size_t i, j, size, limit, newsz;
	char escaped = FALSE;

	if(str == NULL)
		return "";

	size = newsz = strlen(str);
	limit = strlen(charsToEncode);

	for(i = 0; i < size; i++) {
		for(j = 0; j < limit; j++) {
			if(str[i] == charsToEncode[j]) {
				/* allocate 2 extra bytes for the escape sequence (' ' -> '%20') */
				newsz += 2;
				break;
			}
		}
	}
	/* allocate new memory to return the encoded URL */
	p = rv = apr_pcalloc(r->pool, newsz + 1); /* +1 for terminating NULL */
	q = str;

	do {
		escaped = FALSE;
		for(i = 0; i < limit; i++) {
			if(*q == charsToEncode[i]) {
				sprintf(p, "%%%x", charsToEncode[i]);
				p+= 3;
				escaped = TRUE;
				break;
			}
		}
		if(escaped == FALSE) {
			*p++ = *q;
		}

		q++;
	} while (*q != '\0');
	*p = '\0';

	return(rv);
}

char *oidc_escape_string(const request_rec *r, const char *str) {
	char *rfc1738 = "+ <>\"%{}|\\^~[]`;/?:@=&#";
	return(oidc_url_encode(r, str, rfc1738));
}

char *oidc_get_current_url(const request_rec *r, const oidc_cfg *c) {
	const apr_port_t port = r->connection->local_addr->port;
	char *scheme, *port_str = "", *url;
	apr_byte_t print_port = TRUE;
#ifdef APACHE2_0
	scheme = (char *) ap_http_method(r);
#else
	scheme = (char *) ap_http_scheme(r);
#endif
	if ((apr_strnatcmp(scheme, "https") == 0) && port == 443)
		print_port = FALSE;
	else if ((apr_strnatcmp(scheme, "http") == 0) && port == 80)
		print_port = FALSE;
	if (print_port)
		port_str = apr_psprintf(r->pool, ":%u", port);
	url = apr_pstrcat(r->pool, scheme, "://",
		r->server->server_hostname,
		port_str, r->uri,
		(r->args != NULL && *r->args != '\0' ? "?" : ""),
		r->args, NULL);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Current URL '%s'", url);
	return url;
}

char *oidc_get_token_response (request_rec *r, oidc_cfg *c, oidc_dir_cfg *d, char *code) {
	char curlError[CURL_ERROR_SIZE];
	oidc_curl_buffer curlBuffer;
	CURL *curl;
	char *rv = NULL;
	struct curl_httppost *formpost=NULL;
	struct curl_httppost *lastptr=NULL;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_get_token_response()");

	curl = curl_easy_init();
	if (curl == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_OIDC: curl_easy_init() error");
		return NULL;
	}

	curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
	curl_easy_setopt(curl, CURLOPT_HEADER, 0L);
	curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 1L);
	curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
	curl_easy_setopt(curl, CURLOPT_ERRORBUFFER, curlError);
	curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
	curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 5L);

	curlBuffer.written = 0;
	memset(curlBuffer.buf, '\0', sizeof(curlBuffer.buf));
	curl_easy_setopt(curl, CURLOPT_WRITEDATA, &curlBuffer);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, oidc_curl_write);

#ifndef LIBCURL_NO_CURLPROTO
	curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS);
	curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTP|CURLPROTO_HTTPS);
#endif

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (c->ssl_validate_server != FALSE ? 1L : 0L));
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (c->ssl_validate_server != FALSE ? 2L : 0L));

	curl_easy_setopt(curl, CURLOPT_USERAGENT, "mod_oidc 1.0");
	curl_easy_setopt(curl, CURLOPT_HTTPPOST, 1L);

	// TODO: we do id/secret POST only now, also support HTTP basic auth
	curl_easy_setopt(curl, CURLOPT_URL, apr_uri_unparse(r->pool, &c->token_endpoint_url, 0));

	curl_formadd(&formpost,
	               &lastptr,
	               CURLFORM_COPYNAME, "grant_type",
	               CURLFORM_COPYCONTENTS, "authorization_code",
	               CURLFORM_END);
	curl_formadd(&formpost,
	               &lastptr,
	               CURLFORM_COPYNAME, "client_id",
	               CURLFORM_COPYCONTENTS, c->client_id,
	               CURLFORM_END);
	curl_formadd(&formpost,
	               &lastptr,
	               CURLFORM_COPYNAME, "client_secret",
	               CURLFORM_COPYCONTENTS, c->client_secret,
	               CURLFORM_END);
	curl_formadd(&formpost,
	               &lastptr,
	               CURLFORM_COPYNAME, "code",
	               CURLFORM_COPYCONTENTS, code,
	               CURLFORM_END);
	curl_formadd(&formpost,
	               &lastptr,
	               CURLFORM_COPYNAME, "redirect_uri",
	               CURLFORM_COPYCONTENTS, apr_uri_unparse(r->pool, &c->redirect_uri, 0),
	               CURLFORM_END);

	curl_easy_setopt(curl, CURLOPT_HTTPPOST, formpost);
	if (curl_easy_perform(curl) != CURLE_OK) {
		ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_OIDC: curl_easy_perform() failed (%s)", curlError);
		goto out;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Code resolve response: %s", curlBuffer.buf);

	rv = apr_pstrndup(r->pool, curlBuffer.buf, strlen(curlBuffer.buf));

out:
	curl_easy_cleanup(curl);
	return rv;
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
				apr_json_value_t *elem = (apr_json_value_t *)aud->value.array->elts[i];
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

	*attrs = apr_table_make(r->pool, 5);
	apr_hash_index_t *hi;
	for (hi = apr_hash_first(r->pool, payload->value.object); hi; hi = apr_hash_next(hi)) {
		const char *k; apr_json_value_t *v;
		apr_hash_this(hi, (const void**)&k, NULL, (void**)&v);
		if (strstr("iss,sub,aud,nonce,exp,iat,azp,at_hash,c_hash,", apr_pstrcat(r->pool, k, ",", NULL))) continue;
		if (v->type == APR_JSON_STRING) {
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "### setting attribute %s=%s", k, v->value.string.p);
			apr_table_set(*attrs, k, v->value.string.p);
		} else if (v->type == APR_JSON_ARRAY) {
			char *csvs = apr_pstrdup(r->pool, "");
			ap_log_rerror(APLOG_MARK, APLOG_NOTICE, 0, r, "### parsing attribute array %s (#%d)", k, v->value.array->nelts);
			for (int i = 0; i < v->value.array->nelts; i++) {
				apr_json_value_t *elem = (apr_json_value_t *)v->value.array->elts[i];
				if (elem->type != APR_JSON_STRING) {
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

	return 0;
}

apr_byte_t oidc_resolve_code(request_rec *r, oidc_cfg *c, oidc_dir_cfg *d, char *code, char **user, apr_table_t **attrs, char **s_id_token) {

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_resolve_code()");

	const char *response = oidc_get_token_response(r, c, d, code);
	if(response == NULL)
		return FALSE;

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "MOD_OIDC: response = %s", response);

	apr_json_value_t *result = NULL;
	apr_status_t status = apr_json_decode(&result, response, strlen(response), r->pool);

	if (status != APR_SUCCESS) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "could not decode response successfully");
		return FALSE;
	}

	if ( (result ==NULL) || (result->type != APR_JSON_OBJECT) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "response did not contain a JSON object");
		return FALSE;
	}

	apr_json_value_t *id_token = apr_hash_get(result->value.object, "id_token", APR_HASH_KEY_STRING);
	if ( (id_token == NULL) || (id_token->type != APR_JSON_STRING) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "response JSON object did not contain an id_token string");
		return FALSE;
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "returned id_token: %s", id_token->value.string.p);

	*s_id_token = apr_pstrdup(r->pool, id_token->value.string.p);

	oidc_parse_id_token(r, id_token->value.string.p, user, attrs);

	return (status == APR_SUCCESS) ? TRUE : FALSE;
}

char *oidc_get_path(request_rec *r) {
	size_t i;
	char *p;
	p = r->parsed_uri.path;
	if (p[0] == '\0')
		return apr_pstrdup(r->pool, "/");
	for (i = strlen(p) - 1; i > 0; i--)
		if (p[i] == '/')
			break;
	return apr_pstrndup(r->pool, p, i + 1);
}

char *oidc_get_dir_scope(request_rec *r) {
	char *rv = NULL, *requestPath = oidc_get_path(r);
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);
	oidc_dir_cfg *d = ap_get_module_config(r->per_dir_config, &oidc_module);
	if (d->dir_scope != NULL) {
		if(strncmp(d->dir_scope, requestPath, strlen(d->dir_scope)) == 0)
			rv = d->dir_scope;
		else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_OIDC: OIDCDirScope (%s) not a substring of request path, using request path (%s) for cookie", d->dir_scope, requestPath);
			rv = requestPath;
		}
	} else {
			rv = requestPath;
	}
	return (rv);
}

void oidc_set_cookie(request_rec *r, char *cookieName, char *cookieValue) {
	char *headerString, *currentCookies;
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_set_cookie()");
	headerString = apr_psprintf(r->pool, "%s=%s%s;Path=%s%s%s", cookieName, cookieValue, ";Secure", oidc_url_encode(r, oidc_get_dir_scope(r), " "), (c->cookie_domain != NULL ? ";Domain=" : ""), (c->cookie_domain != NULL ? c->cookie_domain : ""));
	/* use r->err_headers_out so we always print our headers (even on 302 redirect) - headers_out only prints on 2xx responses */
	apr_table_add(r->err_headers_out, "Set-Cookie", headerString);
	if((currentCookies = (char *) apr_table_get(r->headers_in, "Cookie")) == NULL)
		apr_table_add(r->headers_in, "Cookie", headerString);
	else
		apr_table_set(r->headers_in, "Cookie", (apr_pstrcat(r->pool, headerString, ";", currentCookies, NULL)));
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Adding outgoing header: Set-Cookie: %s", headerString);
	return;
}

char *oidc_get_authorization_endpoint(request_rec *r, oidc_cfg *c) {
	apr_uri_t test;
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_get_authorization_endpoint()");
	memset(&test, '\0', sizeof(apr_uri_t));
	if(memcmp(&c->authorization_endpoint_url, &test, sizeof(apr_uri_t)) == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_OIDC: OIDCAuthorizationEndpoint null (not set?)");
		return NULL;
	}
	return(apr_uri_unparse(r->pool, &c->authorization_endpoint_url, 0));
}

void oidc_redirect(request_rec *r, oidc_cfg *c) {
	// TODO:
	// a) use nonce and state correctly because we set the id_token as a cookie: ask John why/how
	// b) bind state cryptographically to a user agent cookie
	char *destination = NULL, *state = NULL;
	char *endpoint = oidc_get_authorization_endpoint(r, c);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_redirect()");
	if(endpoint == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "MOD_OIDC: Cannot redirect request (no OIDCAuthorizationURL)");
		return;
	}
	oidc_encrypt_base64url_encode_string(r, &state, oidc_get_current_url(r, c));
	destination = apr_psprintf(r->pool, "%s%sresponse_type=%s&scope=%s&client_id=%s&state=%s&redirect_uri=%s", endpoint, (strchr(endpoint, '?') != NULL ? "&" : "?"), "code", oidc_escape_string(r, c->scope), oidc_escape_string(r, c->client_id), state, oidc_escape_string(r, apr_uri_unparse(r->pool, &c->redirect_uri, 0)));
	apr_table_add(r->headers_out, "Location", destination);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Adding outgoing header: Location: %s", destination);

}

apr_byte_t oidc_is_valid_cookie(request_rec *r, oidc_cfg *c, char *cookie, char **user, apr_table_t **attrs) {
	oidc_dir_cfg *d = ap_get_module_config(r->per_dir_config, &oidc_module);

	char *id_token = NULL;
	oidc_base64url_decode_decrypt_string(r, &id_token, cookie);
	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "entering oidc_is_valid_cookie()");
	oidc_parse_id_token(r, id_token, user, attrs);
	return TRUE;
}

/* Normalize a string for use as an HTTP Header Name.  Any invalid
 * characters (per http://tools.ietf.org/html/rfc2616#section-4.2 and
 * http://tools.ietf.org/html/rfc2616#section-2.2) are replaced with
 * a dash ('-') character. */
char *oidc_normalize_header_name(const request_rec *r, const char *str)
{
        /* token = 1*<any CHAR except CTLs or separators>
         * CTL = <any US-ASCII control character
         *          (octets 0 - 31) and DEL (127)>
         * separators = "(" | ")" | "<" | ">" | "@"
         *              | "," | ";" | ":" | "\" | <">
         *              | "/" | "[" | "]" | "?" | "="
         *              | "{" | "}" | SP | HT */
        const char *separators = "()<>@,;:\\\"/[]?={} \t";

        char *ns = apr_pstrdup(r->pool, str);
        size_t i;
        for (i = 0; i < strlen(ns); i++) {
                if (ns[i] < 32 || ns[i] == 127) ns[i] = '-';
                else if (strchr(separators, ns[i]) != NULL) ns[i] = '-';
        }
        return ns;
}

static int oidc_set_attribute_header(void* rec, const char* key, const char* value) {
	request_rec* r = (request_rec *)rec;
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);
	apr_table_set(r->headers_in, apr_psprintf(r->pool, "%s%s", c->attribute_prefix, oidc_normalize_header_name(r, key)), value);
	return 1;
}

static void oidc_set_attribute_headers(request_rec *r, apr_table_t *attrs) {
	if (attrs != NULL) {
		apr_table_do(oidc_set_attribute_header, r, attrs, NULL);
	}
}

static int oidc_check_user_id(request_rec *r) {
	char *code = NULL, *state = NULL;
	char *cookieString = NULL;
	char *remoteUser = NULL;
	apr_table_t *attrs = NULL;

	oidc_cfg *c;
	oidc_dir_cfg *d;

	if(ap_auth_type(r) == NULL || apr_strnatcasecmp((const char *) ap_auth_type(r), "openid-connect") != 0)
		return DECLINED;

	c = ap_get_module_config(r->server->module_config, &oidc_module);
	d = ap_get_module_config(r->per_dir_config, &oidc_module);

	if (ap_is_initial_req(r) && d->scrub_request_headers) {
		oidc_scrub_request_headers(r, c, d);
	}

	ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "Entering oidc_check_user_id()");

	oidc_get_code_and_state(r, &code, &state);
	cookieString = oidc_get_cookie(r, d->cookie);

	if (code != NULL) {
		char *id_token = NULL;
		if (oidc_resolve_code(r, c, d, code, &remoteUser, &attrs, &id_token)) {
			char *encrypted_token = NULL;
			oidc_encrypt_base64url_encode_string(r, &encrypted_token, id_token);
			oidc_set_cookie(r, d->cookie, encrypted_token);
			r->user = remoteUser;
			if (d->authn_header != NULL)
				apr_table_set(r->headers_in, d->authn_header, remoteUser);
			apr_table_add(r->headers_out, "Location", state);
			return HTTP_MOVED_TEMPORARILY;
		} else {
			/* sometimes, pages that automatically refresh will re-send the code parameter, so let's check any cookies presented or return an error if none */
			if(cookieString == NULL)
				return HTTP_UNAUTHORIZED;
		}
	}

	if(cookieString == NULL) {
		/* redirect the user to the OIDC OP  since they have no cookie and no ticket */
		oidc_redirect(r, c);
		return HTTP_MOVED_TEMPORARILY;
	} else {
		if (!ap_is_initial_req(r)) {
			if(r->main != NULL)
				remoteUser = r->main->user;
			else if (r->prev != NULL)
				remoteUser = r->prev->user;
			else {
				oidc_redirect(r, c);
				return HTTP_MOVED_TEMPORARILY;
			}
			ap_log_rerror(APLOG_MARK, APLOG_DEBUG, 0, r, "recycling user '%s' from initial request for sub request", remoteUser);
		} else if(!oidc_is_valid_cookie(r, c, cookieString, &remoteUser, &attrs)) {
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

static int oidc_auth_checker(request_rec *r) {
	// TODO: when attributes are resolved and stored (copy the file caching mechanism from mod_auth_cas...)
	// we can parse expressions here that match and autorize on attributes
	return DECLINED;
}

#if defined(OPENSSL_THREADS) && APR_HAS_THREADS

static apr_thread_mutex_t **ssl_locks;
static int ssl_num_locks;

static void oidc_ssl_locking_callback(int mode, int type, const char *file, int line) {
	if(type < ssl_num_locks) {
		if (mode & CRYPTO_LOCK)
			apr_thread_mutex_lock(ssl_locks[type]);
		else
			apr_thread_mutex_unlock(ssl_locks[type]);
	}
}

#ifdef OPENSSL_NO_THREADID
static unsigned long oidc_ssl_id_callback(void) {
	return (unsigned long) apr_os_thread_current();
}
#else
static void oidc_ssl_id_callback(CRYPTO_THREADID *id)
{
	CRYPTO_THREADID_set_numeric(id, (unsigned long) apr_os_thread_current());
}
#endif /* OPENSSL_NO_THREADID */

#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */

apr_status_t oidc_cleanup(void *data) {
	server_rec *s = (server_rec *) data;
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "entering oidc_cleanup()");
#if (defined (OPENSSL_THREADS) && APR_HAS_THREADS)
	if(CRYPTO_get_locking_callback() == oidc_ssl_locking_callback)
		CRYPTO_set_locking_callback(NULL);
#ifdef OPENSSL_NO_THREADID
	if(CRYPTO_get_id_callback() == oidc_ssl_id_callback)
		CRYPTO_set_id_callback(NULL);
#else
	if(CRYPTO_THREADID_get_callback() == oidc_ssl_id_callback)
		CRYPTO_THREADID_set_callback(NULL);
#endif /* OPENSSL_NO_THREADID */

#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */
	curl_global_cleanup();
	ap_log_error(APLOG_MARK, APLOG_DEBUG, 0, s, "exiting oidc_cleanup()");
	return APR_SUCCESS;
}

int oidc_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s) {
	const char *userdata_key = "auth_oidc_init";
	void *data;
	int i;

	/* Since the post_config hook is invoked twice (once
	 * for 'sanity checking' of the config and once for
	 * the actual server launch, we have to use a hack
	 * to not run twice
	 */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);

	if(data) {
		curl_global_init(CURL_GLOBAL_ALL);

#if (defined(OPENSSL_THREADS) && APR_HAS_THREADS)
		ssl_num_locks = CRYPTO_num_locks();
		ssl_locks = apr_pcalloc(s->process->pool, ssl_num_locks * sizeof(*ssl_locks));

		for(i = 0; i < ssl_num_locks; i++)
			apr_thread_mutex_create(&(ssl_locks[i]), APR_THREAD_MUTEX_DEFAULT, s->process->pool);

#ifdef OPENSSL_NO_THREADID
		if(CRYPTO_get_locking_callback() == NULL && CRYPTO_get_id_callback() == NULL) {
			CRYPTO_set_locking_callback(oidc_ssl_locking_callback);
			CRYPTO_set_id_callback(oidc_ssl_id_callback);
		}
#else
		if(CRYPTO_get_locking_callback() == NULL && CRYPTO_THREADID_get_callback() == NULL) {
			CRYPTO_set_locking_callback(oidc_ssl_locking_callback);
			CRYPTO_THREADID_set_callback(oidc_ssl_id_callback);
		}
#endif /* OPENSSL_NO_THREADID */
#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */
		apr_pool_cleanup_register(pool, s, oidc_cleanup, apr_pool_cleanup_null);
	}

	apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);

	/*
	 * Apache has a base vhost that true vhosts derive from.
	 * There are two startup scenarios:
	 *
	 * 1. Only the base vhost contains OIDC settings.
	 *    No server configs have been merged.
	 *    Only the base vhost needs to be checked.
	 *
	 * 2. The base vhost contains zero or more OIDC settings.
	 *    One or more vhosts override these.
	 *    These vhosts have a merged config.
	 *    All merged configs need to be checked.
	 */
//	if (!merged_vhost_configs_exist(s)) {
		/* nothing merged, only check the base vhost */
//		return check_vhost_config(pool, s);
//	}

	if (oidc_aes_init(s)) {
		ap_log_error(APLOG_MARK, APLOG_WARNING, 0, s, "MOD_OIDC: Couldn't initialize AES cipher.");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

static void oidc_register_hooks(apr_pool_t *pool) {
	static const char *const authzSucc[] = { "mod_authz_user.c", NULL };
	ap_hook_post_config(oidc_post_config, NULL, NULL, APR_HOOK_LAST);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	ap_hook_check_access_ex(
		oidc_check_user_id,
		NULL,
		NULL,
		APR_HOOK_MIDDLE,
		AP_AUTH_INTERNAL_PER_URI);
#else
	ap_hook_check_user_id(oidc_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
#endif
	ap_hook_auth_checker(oidc_auth_checker, NULL, authzSucc, APR_HOOK_MIDDLE);
}

static const command_rec oidc_cmds[] = {
		AP_INIT_FLAG("OIDCSSLValidateServer", oidc_set_flag_slot, (void*)APR_OFFSETOF(oidc_cfg, ssl_validate_server), RSRC_CONF, "Require validation of the OpenID Connect OP SSL server certificate for successful authentication (On or Off)"),
		AP_INIT_TAKE1("OIDCClientID", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, client_id), RSRC_CONF, "Client identifier used in calls to OpenID Connect OP."),
		AP_INIT_TAKE1("OIDCClientSecret", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, client_secret), RSRC_CONF, "Client secret used in calls to OpenID Connect OP."),
		AP_INIT_TAKE1("OIDCRedirectURI", oidc_set_uri_slot, (void *)APR_OFFSETOF(oidc_cfg, redirect_uri), RSRC_CONF, "Define the Redirect URI (e.g.: https://localhost:9031/protected/return/uri"),
		AP_INIT_TAKE1("OIDCIssuer", oidc_set_string_slot, (void*)APR_OFFSETOF(oidc_cfg, issuer), RSRC_CONF, "OpenID Connect OP issuer identifier."),
		AP_INIT_TAKE1("OIDCAuthorizationEndpoint", oidc_set_uri_slot, (void *)APR_OFFSETOF(oidc_cfg, authorization_endpoint_url), RSRC_CONF, "Define the OpenID OP Authorization Endpoint URL (e.g.: https://localhost:9031/as/authz.oidc)"),
		AP_INIT_TAKE1("OIDCTokenEndpoint", oidc_set_uri_slot, (void *)APR_OFFSETOF(oidc_cfg, token_endpoint_url), RSRC_CONF, "Define the OpenID OP Token Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
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
	oidc_cmds,
	oidc_register_hooks
};
