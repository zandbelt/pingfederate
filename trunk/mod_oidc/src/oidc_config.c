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

#include <apr.h>
#include <apr_errno.h>
#include <apr_strings.h>
#include <apr_portable.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>
#include <ap_provider.h>

#include <curl/curl.h>

#include "mod_oidc.h"

/* validate SSL server certificates by default */
#define OIDC_DEFAULT_SSL_VALIDATE_SERVER 1
/* default token endpoint authentication method */
#define OIDC_DEFAULT_ENDPOINT_AUTH "client_secret_basic"
/* default scope requested from the OP */
#define OIDC_DEFAULT_SCOPE "openid"
/* default claim delimiter for multi-valued claims passed in a HTTP header */
#define OIDC_DEFAULT_CLAIM_DELIMITER ","
/* default prefix for claim names being passed in HTTP headers */
#define OIDC_DEFAULT_CLAIM_PREFIX "OIDC_CLAIM_"
/* default name of the session cookie */
#define OIDC_DEFAULT_COOKIE "mod-oidc"
/* default for the HTTP header name in which the remote user name is passed */
#define OIDC_DEFAULT_AUTHN_HEADER NULL
/* scrub HTTP headers by default unless overridden (and insecure) */
#define OIDC_DEFAULT_SCRUB_REQUEST_HEADERS 1
/* default client_name the client uses for dynamic client registration */
#define OIDC_DEFAULT_CLIENT_NAME "OpenID Connect Apache Module (mod_oidc)"
/* timeouts in seconds for HTTP calls that may take a long time */
#define OIDC_DEFAULT_HTTP_TIMEOUT_LONG  60
/* timeouts in seconds for HTTP calls that should take a short time (registry/discovery related) */
#define OIDC_DEFAULT_HTTP_TIMEOUT_SHORT  5
/* default session storage type */
#define OIDC_DEFAULT_SESSION_TYPE OIDC_SESSION_TYPE_22_CACHE_FILE
/* timeout in seconds after which state expires */
#define OIDC_DEFAULT_STATE_TIMEOUT 300
/* default OpenID Connect authorization response type */
#define OIDC_DEFAULT_RESPONSE_TYPE "code"
/* default duration in seconds after which retrieved JWS should be refreshed */
#define OIDC_DEFAULT_JWKS_REFRESH_INTERVAL 3600
/* default max cache size for shm */
#define OIDC_DEFAULT_CACHE_SHM_SIZE 500
/* for issued-at timestamp (iat) checking */
#define OIDC_DEFAULT_IDTOKEN_IAT_SLACK 600

extern module AP_MODULE_DECLARE_DATA oidc_module;

/*
 * set a boolean value in the server config
 */
const char *oidc_set_flag_slot(cmd_parms *cmd, void *struct_ptr, int arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);
	return ap_set_flag_slot(cmd, cfg, arg);
}

/*
 * set a string value in the server config
 */
const char *oidc_set_string_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);
	return ap_set_string_slot(cmd, cfg, arg);
}

/*
 * set an integer value in the server config
 */
const char *oidc_set_int_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);
	return ap_set_int_slot(cmd, cfg, arg);
}

/*
 * set a URL value in the server config
 */
static const char *oidc_set_url_slot_type(cmd_parms *cmd, void *ptr,
		const char *arg, const char *type) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);
	apr_uri_t url;
	if (apr_uri_parse(cmd->pool, arg, &url) != APR_SUCCESS) {
		return apr_psprintf(cmd->pool,
				"oidc_set_url_slot_type: configuration value '%s' could not be parsed as a URL!",
				arg);
	}

	if (url.scheme == NULL) {
		return apr_psprintf(cmd->pool,
				"oidc_set_url_slot_type: configuration value '%s' could not be parsed as a URL (no scheme set)!",
				arg);
	}

	if (type == NULL) {
		if ((strcmp(url.scheme, "http") != 0)
				&& (strcmp(url.scheme, "https") != 0)) {
			return apr_psprintf(cmd->pool,
					"oidc_set_url_slot_type: configuration value '%s' could not be parsed as a HTTP/HTTPs URL (scheme != http/https)!",
					arg);
		}
	} else if (strcmp(url.scheme, type) != 0) {
		return apr_psprintf(cmd->pool,
				"oidc_set_url_slot_type: configuration value '%s' could not be parsed as a \"%s\" URL (scheme == %s != \"%s\")!",
				arg, type, url.scheme, type);
	}

	if (url.hostname == NULL) {
		return apr_psprintf(cmd->pool,
				"oidc_set_url_slot_type: configuration value '%s' could not be parsed as a HTTP/HTTPs URL (no hostname set, check your slashes)!",
				arg);
	}
	return ap_set_string_slot(cmd, cfg, arg);
}

/*
 * set a HTTPS value in the server config
 */
const char *oidc_set_https_slot(cmd_parms *cmd, void *ptr, const char *arg) {
	return oidc_set_url_slot_type(cmd, ptr, arg, "https");
}

/*
 * set a HTTPS/HTTP value in the server config
 */
const char *oidc_set_url_slot(cmd_parms *cmd, void *ptr, const char *arg) {
	return oidc_set_url_slot_type(cmd, ptr, arg, NULL);
}

/*
 * set a directory value in the server config
 */
// TODO: it's not really a syntax error... (could be fixed at runtime but then we'd have to restart the server)
const char *oidc_set_dir_slot(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);

	char s_err[128];
	apr_dir_t *dir;
	apr_status_t rc = APR_SUCCESS;

	/* ensure the directory exists */
	if ((rc = apr_dir_open(&dir, arg, cmd->pool)) != APR_SUCCESS) {
		return apr_psprintf(cmd->pool,
				"oidc_set_dir_slot: could not access directory '%s' (%s)", arg,
				apr_strerror(rc, s_err, sizeof(s_err)));
	}

	/* and cleanup... */
	if ((rc = apr_dir_close(dir)) != APR_SUCCESS) {
		return apr_psprintf(cmd->pool,
				"oidc_set_dir_slot: could not close directory '%s' (%s)", arg,
				apr_strerror(rc, s_err, sizeof(s_err)));
	}

	return ap_set_string_slot(cmd, cfg, arg);
}

/*
 * set the cookie domain in the server config and check it syntactically
 */
const char *oidc_set_cookie_domain(cmd_parms *cmd, void *ptr, const char *value) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);
	size_t sz, limit;
	char d;
	limit = strlen(value);
	for (sz = 0; sz < limit; sz++) {
		d = value[sz];
		if ((d < '0' || d > '9') && (d < 'a' || d > 'z') && (d < 'A' || d > 'Z')
				&& d != '.' && d != '-') {
			return (apr_psprintf(cmd->pool,
					"oidc_set_cookie_domain: invalid character (%c) in OIDCCookieDomain",
					d));
		}
	}
	cfg->cookie_domain = apr_pstrdup(cmd->pool, value);
	return NULL;
}

/*
 * set the session storage type
 */
const char *oidc_set_session_type(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);

	if (strcmp(arg, "file") == 0) {
		cfg->session_type = OIDC_SESSION_TYPE_22_CACHE_FILE;
	} else if (strcmp(arg, "cookie") == 0) {
		cfg->session_type = OIDC_SESSION_TYPE_22_COOKIE;
	} else {
		return (apr_psprintf(cmd->pool,
				"oidc_set_session_type: invalid value for OIDCSessionType (%s); must be one of \"file\" or \"cookie\"",
				arg));
	}

	return NULL;
}

/*
 * set the cache type
 */
const char *oidc_set_cache_type(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);

	if (strcmp(arg, "file") == 0) {
		cfg->cache = &oidc_cache_file;
	} else if (strcmp(arg, "memcache") == 0) {
		cfg->cache = &oidc_cache_memcache;
	} else if (strcmp(arg, "shm") == 0) {
		cfg->cache = &oidc_cache_shm;
	} else {
		return (apr_psprintf(cmd->pool,
				"oidc_set_cache_type: invalid value for OIDCCacheType (%s); must be one of \"file\", \"memcache\" or \"shm\"",
				arg));
	}

	cfg->cache_cfg = cfg->cache->create_config ? cfg->cache->create_config(cmd->server->process->pool) : NULL;

	return NULL;
}

/*
 * set an authentication method for an endpoint and check it is one that we support
 */
const char *oidc_set_endpoint_auth_slot(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);

	if ((apr_strnatcmp(arg, "client_secret_post") == 0)
			|| (apr_strnatcmp(arg, "client_secret_basic") == 0)) {

		return ap_set_string_slot(cmd, cfg, arg);
	}
	return "parameter must be 'client_secret_post' or 'client_secret_basic'";
}

/*
 * set the response type used
 */
const char *oidc_set_response_type(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);

	if ((apr_strnatcmp(arg, "code") == 0)
			|| (apr_strnatcmp(arg, "id_token") == 0)
			|| (apr_strnatcmp(arg, "id_token token") == 0)
			|| (apr_strnatcmp(arg, "token id_token") == 0)) {

		return ap_set_string_slot(cmd, cfg, arg);
	}
	return "parameter must be one of 'code', 'id_token', 'id_token token' or 'token id_token'";
}

/*
 * set the id_token signing algorithm to be used by the OP
 * TODO: align supported functions with oidc_crypto_jwt_alg2padding and metadata_is_valid function
 */
const char *oidc_set_id_token_alg(cmd_parms *cmd, void *struct_ptr,
		const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(
			cmd->server->module_config, &oidc_module);

	if ((apr_strnatcmp(arg, "RS256") == 0) || (apr_strnatcmp(arg, "RS384") == 0)
			|| (apr_strnatcmp(arg, "RS512") == 0)
			|| (apr_strnatcmp(arg, "PS256") == 0)
			|| (apr_strnatcmp(arg, "PS384") == 0)
			|| (apr_strnatcmp(arg, "PS512") == 0)
			|| (apr_strnatcmp(arg, "HS256") == 0)
			|| (apr_strnatcmp(arg, "HS384") == 0)
			|| (apr_strnatcmp(arg, "HS512") == 0)) {

		return ap_set_string_slot(cmd, cfg, arg);
	}
	return "parameter must be one of 'RS256', 'RS384', 'RS512', 'HS256', 'HS384', 'HS512', 'PS256', 'PS384' or 'PS512'";
}

/*
 * get the current path from the request in a normalized way
 */
static char *oidc_get_path(request_rec *r) {
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

/*
 * get the cookie path setting and check that it matches the request path; cook it up if it is not set
 */
char *oidc_get_cookie_path(request_rec *r) {
	char *rv = NULL, *requestPath = oidc_get_path(r);
	oidc_dir_cfg *d = ap_get_module_config(r->per_dir_config, &oidc_module);
	if (d->cookie_path != NULL) {
		if (strncmp(d->cookie_path, requestPath, strlen(d->cookie_path)) == 0)
			rv = d->cookie_path;
		else {
			ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
					"oidc_get_cookie_path: OIDCCookiePath (%s) not a substring of request path, using request path (%s) for cookie",
					d->cookie_path, requestPath);
			rv = requestPath;
		}
	} else {
		rv = requestPath;
	}
	return (rv);
}

/*
 * create a new server config record with defaults
 */
void *oidc_create_server_config(apr_pool_t *pool, server_rec *svr) {
	oidc_cfg *c = apr_pcalloc(pool, sizeof(oidc_cfg));

	c->merged = FALSE;

	c->redirect_uri = NULL;
	c->discover_url = NULL;
	c->id_token_alg = NULL;

	c->provider.issuer = NULL;
	c->provider.authorization_endpoint_url = NULL;
	c->provider.token_endpoint_url = NULL;
	c->provider.token_endpoint_auth = OIDC_DEFAULT_ENDPOINT_AUTH;
	c->provider.userinfo_endpoint_url = NULL;
	c->provider.client_id = NULL;
	c->provider.client_secret = NULL;

	c->provider.ssl_validate_server = OIDC_DEFAULT_SSL_VALIDATE_SERVER;
	c->provider.client_name = OIDC_DEFAULT_CLIENT_NAME;
	c->provider.client_contact = NULL;
	c->provider.scope = OIDC_DEFAULT_SCOPE;
	c->provider.response_type = OIDC_DEFAULT_RESPONSE_TYPE;
	c->provider.jwks_refresh_interval = OIDC_DEFAULT_JWKS_REFRESH_INTERVAL;
	c->provider.idtoken_iat_slack = OIDC_DEFAULT_IDTOKEN_IAT_SLACK;

	c->oauth.ssl_validate_server = OIDC_DEFAULT_SSL_VALIDATE_SERVER;
	c->oauth.client_id = NULL;
	c->oauth.client_secret = NULL;
	c->oauth.validate_endpoint_url = NULL;
	c->oauth.validate_endpoint_auth = OIDC_DEFAULT_ENDPOINT_AUTH;

	c->cache = &oidc_cache_file;
	c->cache_cfg = c->cache->create_config? c->cache->create_config(pool) : NULL;
	c->cache_file_dir = NULL;
	c->cache_memcache_servers = NULL;
	c->cache_shm_size_max = OIDC_DEFAULT_CACHE_SHM_SIZE;

	c->metadata_dir = NULL;
	c->session_type = OIDC_DEFAULT_SESSION_TYPE;

	c->http_timeout_long = OIDC_DEFAULT_HTTP_TIMEOUT_LONG;
	c->http_timeout_short = OIDC_DEFAULT_HTTP_TIMEOUT_SHORT;
	c->state_timeout = OIDC_DEFAULT_STATE_TIMEOUT;

	c->cookie_domain = NULL;
	c->claim_delimiter = OIDC_DEFAULT_CLAIM_DELIMITER;
	c->claim_prefix = OIDC_DEFAULT_CLAIM_PREFIX;
	c->crypto_passphrase = NULL;

	c->scrub_request_headers = OIDC_DEFAULT_SCRUB_REQUEST_HEADERS;

	return c;
}

/*
 * merge a new server config with a base one
 */
void *oidc_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD) {
	oidc_cfg *c = apr_pcalloc(pool, sizeof(oidc_cfg));
	oidc_cfg *base = BASE;
	oidc_cfg *add = ADD;

	c->merged = TRUE;

	c->redirect_uri =
			add->redirect_uri != NULL ? add->redirect_uri : base->redirect_uri;
	c->discover_url =
			add->discover_url != NULL ? add->discover_url : base->discover_url;
	c->id_token_alg =
			add->id_token_alg != NULL ? add->id_token_alg : base->id_token_alg;

	c->provider.issuer =
			add->provider.issuer != NULL ?
					add->provider.issuer : base->provider.issuer;
	c->provider.authorization_endpoint_url =
			add->provider.authorization_endpoint_url != NULL ?
					add->provider.authorization_endpoint_url :
					base->provider.authorization_endpoint_url;
	c->provider.token_endpoint_url =
			add->provider.token_endpoint_url != NULL ?
					add->provider.token_endpoint_url :
					base->provider.token_endpoint_url;
	c->provider.token_endpoint_auth =
			strcmp(add->provider.token_endpoint_auth,
			OIDC_DEFAULT_ENDPOINT_AUTH) != 0 ?
					add->provider.token_endpoint_auth :
					base->provider.token_endpoint_auth;
	c->provider.userinfo_endpoint_url =
			add->provider.userinfo_endpoint_url != NULL ?
					add->provider.userinfo_endpoint_url :
					base->provider.userinfo_endpoint_url;
	c->provider.client_id =
			add->provider.client_id != NULL ?
					add->provider.client_id : base->provider.client_id;
	c->provider.client_secret =
			add->provider.client_secret != NULL ?
					add->provider.client_secret : base->provider.client_secret;

	c->provider.ssl_validate_server =
			add->provider.ssl_validate_server
					!= OIDC_DEFAULT_SSL_VALIDATE_SERVER ?
					add->provider.ssl_validate_server :
					base->provider.ssl_validate_server;
	c->provider.client_name =
			strcmp(add->provider.client_name, OIDC_DEFAULT_CLIENT_NAME) != 0 ?
					add->provider.client_name : base->provider.client_name;
	c->provider.client_contact =
			add->provider.client_contact != NULL ?
					add->provider.client_contact :
					base->provider.client_contact;
	c->provider.scope =
			strcmp(add->provider.scope, OIDC_DEFAULT_SCOPE) != 0 ?
					add->provider.scope : base->provider.scope;
	c->provider.response_type =
			strcmp(add->provider.response_type, OIDC_DEFAULT_RESPONSE_TYPE)
					!= 0 ?
					add->provider.response_type : base->provider.response_type;
	c->provider.jwks_refresh_interval =
			add->provider.jwks_refresh_interval
					!= OIDC_DEFAULT_JWKS_REFRESH_INTERVAL ?
					add->provider.jwks_refresh_interval :
					base->provider.jwks_refresh_interval;
	c->provider.idtoken_iat_slack =
			add->provider.idtoken_iat_slack != OIDC_DEFAULT_IDTOKEN_IAT_SLACK ?
					add->provider.idtoken_iat_slack :
					base->provider.idtoken_iat_slack;


	c->oauth.ssl_validate_server =
			add->oauth.ssl_validate_server != OIDC_DEFAULT_SSL_VALIDATE_SERVER ?
					add->oauth.ssl_validate_server :
					base->oauth.ssl_validate_server;
	c->oauth.client_id =
			add->oauth.client_id != NULL ?
					add->oauth.client_id : base->oauth.client_id;
	c->oauth.client_secret =
			add->oauth.client_secret != NULL ?
					add->oauth.client_secret : base->oauth.client_secret;
	c->oauth.validate_endpoint_url =
			add->oauth.validate_endpoint_url != NULL ?
					add->oauth.validate_endpoint_url :
					base->oauth.validate_endpoint_url;
	c->oauth.validate_endpoint_auth =
			strcmp(add->oauth.validate_endpoint_auth,
			OIDC_DEFAULT_ENDPOINT_AUTH) != 0 ?
					add->oauth.validate_endpoint_auth :
					base->oauth.validate_endpoint_auth;

	c->http_timeout_long =
			add->http_timeout_long != OIDC_DEFAULT_HTTP_TIMEOUT_LONG ?
					add->http_timeout_long : base->http_timeout_long;
	c->http_timeout_short =
			add->http_timeout_short != OIDC_DEFAULT_HTTP_TIMEOUT_SHORT ?
					add->http_timeout_short : base->http_timeout_short;
	c->state_timeout =
			add->state_timeout != OIDC_DEFAULT_STATE_TIMEOUT ?
					add->state_timeout : base->state_timeout;

	if (add->cache != &oidc_cache_file) {
		c->cache = add->cache;
		c->cache_cfg = add->cache_cfg;
	} else {
		c->cache = base->cache;
		c->cache_cfg = base->cache_cfg;
	}

	c->cache_file_dir =
			add->cache_file_dir != NULL ?
					add->cache_file_dir : base->cache_file_dir;
	c->cache_memcache_servers =
			add->cache_memcache_servers != NULL ?
					add->cache_memcache_servers : base->cache_memcache_servers;
	c->cache_shm_size_max =
			add->cache_shm_size_max != OIDC_DEFAULT_CACHE_SHM_SIZE ?
					add->cache_shm_size_max : base->cache_shm_size_max;

	c->metadata_dir =
			add->metadata_dir != NULL ? add->metadata_dir : base->metadata_dir;
	c->session_type =
			add->session_type != OIDC_DEFAULT_SESSION_TYPE ?
					add->session_type : base->session_type;

	c->cookie_domain =
			add->cookie_domain != NULL ?
					add->cookie_domain : base->cookie_domain;
	c->claim_delimiter =
			strcmp(add->claim_delimiter, OIDC_DEFAULT_CLAIM_DELIMITER) != 0 ?
					add->claim_delimiter : base->claim_delimiter;
	c->claim_prefix =
			strcmp(add->claim_prefix, OIDC_DEFAULT_CLAIM_PREFIX) != 0 ?
					add->claim_prefix : base->claim_prefix;
	c->crypto_passphrase =
			add->crypto_passphrase != NULL ?
					add->crypto_passphrase : base->crypto_passphrase;

	c->scrub_request_headers =
			add->scrub_request_headers != OIDC_DEFAULT_SCRUB_REQUEST_HEADERS ?
					add->scrub_request_headers : base->scrub_request_headers;

	return c;
}

/*
 * create a new directory config record with defaults
 */
void *oidc_create_dir_config(apr_pool_t *pool, char *path) {
	oidc_dir_cfg *c = apr_pcalloc(pool, sizeof(oidc_dir_cfg));
	c->cookie = OIDC_DEFAULT_COOKIE;
	c->cookie_path = NULL;
	c->authn_header = OIDC_DEFAULT_AUTHN_HEADER;
	return (c);
}

/*
 * merge a new directory config with a base one
 */
void *oidc_merge_dir_config(apr_pool_t *pool, void *BASE, void *ADD) {
	oidc_dir_cfg *c = apr_pcalloc(pool, sizeof(oidc_dir_cfg));
	oidc_dir_cfg *base = BASE;
	oidc_dir_cfg *add = ADD;
	c->cookie = (
			apr_strnatcasecmp(add->cookie, OIDC_DEFAULT_COOKIE) != 0 ?
					add->cookie : base->cookie);
	c->cookie_path = (
			add->cookie_path != NULL ? add->cookie_path : base->cookie_path);
	c->authn_header = (
			add->authn_header != OIDC_DEFAULT_AUTHN_HEADER ?
					add->authn_header : base->authn_header);
	return (c);
}

/*
 * report a config error
 */
static int oidc_check_config_error(server_rec *s, const char *config_str) {
	ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
			"oidc_check_config_error: mandatory parameter '%s' is not set",
			config_str);
	return HTTP_INTERNAL_SERVER_ERROR;
}

/*
 * check the config required for the OpenID Connect RP role
 */
static int oidc_check_config_oidc(server_rec *s, oidc_cfg *c) {

	if ((c->metadata_dir == NULL) && (c->provider.issuer == NULL)) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s,
				"oidc_check_config_oidc: one of 'OIDCProviderIssuer' or 'OIDCMetadataDir' must be set");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	if (c->redirect_uri == NULL)
		return oidc_check_config_error(s, "OIDCRedirectURI");
	if (c->crypto_passphrase == NULL)
		return oidc_check_config_error(s, "OIDCCryptoPassphrase");

	if (c->metadata_dir == NULL) {
		if (c->provider.issuer == NULL)
			return oidc_check_config_error(s, "OIDCProviderIssuer");
		if (c->provider.authorization_endpoint_url == NULL)
			return oidc_check_config_error(s,
					"OIDCProviderAuthorizationEndpoint");
		// TODO: this depends on the configured OIDCResponseType now
		if (c->provider.token_endpoint_url == NULL)
			return oidc_check_config_error(s, "OIDCProviderTokenEndpoint");
		if (c->provider.client_id == NULL)
			return oidc_check_config_error(s, "OIDCClientID");
		// TODO: this depends on the configured OIDCResponseType now
		if (c->provider.client_secret == NULL)
			return oidc_check_config_error(s, "OIDCClientSecret");
	}

	return OK;
}

/*
 * check the config required for the OAuth 2.0 RS role
 */
static int oidc_check_config_oauth(server_rec *s, oidc_cfg *c) {

	if (c->oauth.client_id == NULL)
		return oidc_check_config_error(s, "OIDCOAuthClientID");

	if (c->oauth.client_secret == NULL)
		return oidc_check_config_error(s, "OIDCOAuthClientSecret");

	if (c->oauth.validate_endpoint_url == NULL)
		return oidc_check_config_error(s, "OIDCOAuthEndpoint");

	return OK;
}

/*
 * check the config of a vhost
 */
static int oidc_config_check_vhost_config(apr_pool_t *pool, server_rec *s) {
	oidc_cfg *cfg = ap_get_module_config(s->module_config, &oidc_module);

	ap_log_error(APLOG_MARK, OIDC_DEBUG, 0, s,
			"oidc_config_check_vhost_config: entering");

	if ((cfg->metadata_dir != NULL) || (cfg->provider.issuer == NULL)
			|| (cfg->redirect_uri != NULL)
			|| (cfg->crypto_passphrase != NULL)) {
		if (oidc_check_config_oidc(s, cfg) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	if ((cfg->oauth.client_id != NULL) || (cfg->oauth.client_secret != NULL)
			|| (cfg->oauth.validate_endpoint_url != NULL)) {
		if (oidc_check_config_oauth(s, cfg) != OK)
			return HTTP_INTERNAL_SERVER_ERROR;
	}

	return OK;
}

/*
 * check the config of a merged vhost
 */
static int oidc_config_check_merged_vhost_configs(apr_pool_t *pool,
		server_rec *s) {
	int status = OK;
	while (s != NULL && status == OK) {
		oidc_cfg *cfg = ap_get_module_config(s->module_config, &oidc_module);
		if (cfg->merged) {
			status = oidc_config_check_vhost_config(pool, s);
		}
		s = s->next;
	}
	return status;
}

/*
 * check if any merged vhost configs exist
 */
static int oidc_config_merged_vhost_configs_exist(server_rec *s) {
	while (s != NULL) {
		oidc_cfg *cfg = ap_get_module_config(s->module_config, &oidc_module);
		if (cfg->merged) {
			return TRUE;
		}
		s = s->next;
	}
	return FALSE;
}

/*
 * SSL initialization magic copied from mod_auth_cas
 */
#if defined(OPENSSL_THREADS) && APR_HAS_THREADS

static apr_thread_mutex_t **ssl_locks;
static int ssl_num_locks;

static void oidc_ssl_locking_callback(int mode, int type, const char *file,
		int line) {
	if (type < ssl_num_locks) {
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
static void oidc_ssl_id_callback(CRYPTO_THREADID *id) {
	CRYPTO_THREADID_set_numeric(id, (unsigned long) apr_os_thread_current());
}
#endif /* OPENSSL_NO_THREADID */

#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */

apr_status_t oidc_cleanup(void *data) {
#if (defined (OPENSSL_THREADS) && APR_HAS_THREADS)
	if (CRYPTO_get_locking_callback() == oidc_ssl_locking_callback)
		CRYPTO_set_locking_callback(NULL);
#ifdef OPENSSL_NO_THREADID
	if (CRYPTO_get_id_callback() == oidc_ssl_id_callback)
	CRYPTO_set_id_callback(NULL);
#else
	if (CRYPTO_THREADID_get_callback() == oidc_ssl_id_callback)
		CRYPTO_THREADID_set_callback(NULL);
#endif /* OPENSSL_NO_THREADID */

#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */
	curl_global_cleanup();
	return APR_SUCCESS;
}

/*
 * handler that is called (twice) after the configuration phase; check if everything is OK
 */
int oidc_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2,
		server_rec *s) {
	const char *userdata_key = "oidc_post_config";
	void *data = NULL;
	int i;

	/* Since the post_config hook is invoked twice (once
	 * for 'sanity checking' of the config and once for
	 * the actual server launch, we have to use a hack
	 * to not run twice
	 */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (data == NULL) {
		apr_pool_userdata_set((const void *) 1, userdata_key,
				apr_pool_cleanup_null, s->process->pool);
		return OK;
	}

	curl_global_init(CURL_GLOBAL_ALL);

#if (defined(OPENSSL_THREADS) && APR_HAS_THREADS)
	ssl_num_locks = CRYPTO_num_locks();
	ssl_locks = apr_pcalloc(s->process->pool,
			ssl_num_locks * sizeof(*ssl_locks));

	for (i = 0; i < ssl_num_locks; i++)
		apr_thread_mutex_create(&(ssl_locks[i]), APR_THREAD_MUTEX_DEFAULT,
				s->process->pool);

#ifdef OPENSSL_NO_THREADID
	if (CRYPTO_get_locking_callback() == NULL && CRYPTO_get_id_callback() == NULL) {
		CRYPTO_set_locking_callback(oidc_ssl_locking_callback);
		CRYPTO_set_id_callback(oidc_ssl_id_callback);
	}
#else
	if (CRYPTO_get_locking_callback() == NULL
			&& CRYPTO_THREADID_get_callback() == NULL) {
		CRYPTO_set_locking_callback(oidc_ssl_locking_callback);
		CRYPTO_THREADID_set_callback(oidc_ssl_id_callback);
	}
#endif /* OPENSSL_NO_THREADID */
#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */
	apr_pool_cleanup_register(pool, s, oidc_cleanup, apr_pool_cleanup_null);

	oidc_session_init();

	server_rec *sp = s;
	while (sp != NULL) {
		oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(sp->module_config,
				&oidc_module);
		if (cfg->cache->post_config != NULL) {
			if (cfg->cache->post_config(sp) != OK) return HTTP_INTERNAL_SERVER_ERROR;
		}
		sp = sp->next;
	}

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
	if (!oidc_config_merged_vhost_configs_exist(s)) {
		/* nothing merged, only check the base vhost */
		return oidc_config_check_vhost_config(pool, s);
	}
	return oidc_config_check_merged_vhost_configs(pool, s);
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
static const authz_provider authz_oidc_provider = {
	&oidc_authz_checker,
	NULL,
};
#endif

/*
 * initialize cache context in child process if required
 */
void oidc_child_init(apr_pool_t *p, server_rec *s) {
	while (s != NULL) {
		oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(s->module_config,
				&oidc_module);
		if (cfg->cache->child_init != NULL) {
			if (cfg->cache->child_init(p, s) != APR_SUCCESS) {
				// TODO: ehrm...
				exit(-1);
			}
		}
		s = s->next;
	}
}

/*
 * register our authentication and authorization functions
 */
void oidc_register_hooks(apr_pool_t *pool) {
	ap_hook_post_config(oidc_post_config, NULL, NULL, APR_HOOK_LAST);
	ap_hook_child_init(oidc_child_init, NULL, NULL, APR_HOOK_MIDDLE);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	ap_hook_check_authn(oidc_check_user_id, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(pool, AUTHZ_PROVIDER_GROUP, "attribute", "0", &authz_oidc_provider, AP_AUTH_INTERNAL_PER_CONF);
#else
	static const char * const authzSucc[] = { "mod_authz_user.c", NULL };
	ap_hook_check_user_id(oidc_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(oidc_auth_checker, NULL, authzSucc, APR_HOOK_MIDDLE);
#endif
}

/*
 * set of configuration primitives
 */
const command_rec oidc_config_cmds[] = {

		AP_INIT_TAKE1("OIDCProviderIssuer", oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.issuer),
				RSRC_CONF, "OpenID Connect OP issuer identifier."),
		AP_INIT_TAKE1("OIDCProviderAuthorizationEndpoint",
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.authorization_endpoint_url),
				RSRC_CONF,
				"Define the OpenID OP Authorization Endpoint URL (e.g.: https://localhost:9031/as/authorization.oauth2)"),
		AP_INIT_TAKE1("OIDCProviderTokenEndpoint",
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.token_endpoint_url),
				RSRC_CONF,
				"Define the OpenID OP Token Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
		AP_INIT_TAKE1("OIDCProviderTokenEndpointAuth",
				oidc_set_endpoint_auth_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.token_endpoint_auth),
				RSRC_CONF,
				"Specify an authentication method for the OpenID OP Token Endpoint (e.g.: client_secret_basic)"),
		AP_INIT_TAKE1("OIDCProviderUserInfoEndpoint",
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.userinfo_endpoint_url),
				RSRC_CONF,
				"Define the OpenID OP UserInfo Endpoint URL (e.g.: https://localhost:9031/idp/userinfo.openid)"),
		AP_INIT_TAKE1("OIDCProviderJwksUri",
				oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, provider.jwks_uri),
				RSRC_CONF,
				"Define the OpenID OP JWKS URL (e.g.: https://macbook:9031/pf/JWKS)"),
		AP_INIT_TAKE1("OIDCResponseType",
				oidc_set_response_type,
				(void *)APR_OFFSETOF(oidc_cfg, provider.response_type),
				RSRC_CONF,
				"The response type (or OpenID Connect Flow) used; must be one of \"code\", \"id_token\", \"id_token token\" or \"token id_token\" (serves as default value for discovered OPs too)"),
		AP_INIT_TAKE1("OIDCIDTokenAlg", oidc_set_id_token_alg,
				(void *)APR_OFFSETOF(oidc_cfg, id_token_alg),
				RSRC_CONF,
				"The algorithm that the OP should use to sign the id_token (used only in dynamic client registration); must be one of [RS256|RS384|RS512|PS256|PS384|PS512]"),
		AP_INIT_FLAG("OIDCSSLValidateServer",
				oidc_set_flag_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.ssl_validate_server),
				RSRC_CONF,
				"Require validation of the OpenID Connect OP SSL server certificate for successful authentication (On or Off)"),
		AP_INIT_TAKE1("OIDCClientName", oidc_set_string_slot,
				(void *) APR_OFFSETOF(oidc_cfg, provider.client_name),
				RSRC_CONF,
				"Define the (client_name) name that the client uses for dynamic registration to the OP."),
		AP_INIT_TAKE1("OIDCClientContact", oidc_set_string_slot,
				(void *) APR_OFFSETOF(oidc_cfg, provider.client_contact),
				RSRC_CONF,
				"Define the contact that the client registers in dynamic registration with the OP."),
		AP_INIT_TAKE1("OIDCScope", oidc_set_string_slot,
				(void *) APR_OFFSETOF(oidc_cfg, provider.scope),
				RSRC_CONF,
				"Define the OpenID Connect scope that is requested from the OP."),
		AP_INIT_TAKE1("OIDCJWKSRefreshInterval",
				oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.jwks_refresh_interval),
				RSRC_CONF,
				"Duration in seconds after which retrieved JWS should be refreshed."),
		AP_INIT_TAKE1("OIDCIDTokenIatSlack",
				oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.idtoken_iat_slack),
				RSRC_CONF,
				"Acceptable offset (both before and after) for checking the \"iat\" (= issued at) timestamp in the id_token."),

		AP_INIT_TAKE1("OIDCClientID", oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.client_id),
				RSRC_CONF,
				"Client identifier used in calls to OpenID Connect OP."),
		AP_INIT_TAKE1("OIDCClientSecret", oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, provider.client_secret),
				RSRC_CONF,
				"Client secret used in calls to OpenID Connect OP."),

		AP_INIT_TAKE1("OIDCRedirectURI", oidc_set_url_slot,
				(void *)APR_OFFSETOF(oidc_cfg, redirect_uri),
				RSRC_CONF,
				"Define the Redirect URI (e.g.: https://localhost:9031/protected/example/)"),
		AP_INIT_TAKE1("OIDCDiscoverURL", oidc_set_url_slot,
				(void *)APR_OFFSETOF(oidc_cfg, discover_url),
				RSRC_CONF,
				"Defines an external IDP Discovery page"),
		AP_INIT_TAKE1("OIDCCookieDomain",
				oidc_set_cookie_domain, NULL, RSRC_CONF,
				"Specify domain element for OIDC session cookie."),
		AP_INIT_TAKE1("OIDCCryptoPassphrase",
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, crypto_passphrase),
				RSRC_CONF,
				"Passphrase used for AES crypto on cookies and state."),
		AP_INIT_TAKE1("OIDCClaimDelimiter",
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, claim_delimiter),
				RSRC_CONF,
				"The delimiter to use when setting multi-valued claims in the HTTP headers."),
		AP_INIT_TAKE1("OIDCClaimPrefix", oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, claim_prefix),
				RSRC_CONF,
				"The prefix to use when setting claims in the HTTP headers."),

		AP_INIT_TAKE1("OIDCOAuthClientID", oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.client_id),
				RSRC_CONF,
				"Client identifier used in calls to OAuth 2.0 Authorization server validation calls."),
		AP_INIT_TAKE1("OIDCOAuthClientSecret",
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.client_secret),
				RSRC_CONF,
				"Client secret used in calls to OAuth 2.0 Authorization server validation calls."),
		AP_INIT_TAKE1("OIDCOAuthEndpoint", oidc_set_https_slot,
				(void *)APR_OFFSETOF(oidc_cfg, oauth.validate_endpoint_url),
				RSRC_CONF,
				"Define the OAuth AS Validation Endpoint URL (e.g.: https://localhost:9031/as/token.oauth2)"),
		AP_INIT_TAKE1("OIDCOAuthEndpointAuth",
				oidc_set_endpoint_auth_slot,
				(void *)APR_OFFSETOF(oidc_cfg, oauth.validate_endpoint_auth),
				RSRC_CONF,
				"Specify an authentication method for the OAuth AS Validation Endpoint (e.g.: client_auth_basic)"),
		AP_INIT_FLAG("OIDCOAuthSSLValidateServer",
				oidc_set_flag_slot,
				(void*)APR_OFFSETOF(oidc_cfg, oauth.ssl_validate_server),
				RSRC_CONF,
				"Require validation of the OAuth 2.0 AS Validation Endpoint SSL server certificate for successful authentication (On or Off)"),

		AP_INIT_TAKE1("OIDCHTTPTimeoutLong", oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, http_timeout_long),
				RSRC_CONF,
				"Timeout for long duration HTTP calls (default)."),
		AP_INIT_TAKE1("OIDCHTTPTimeoutShort", oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, http_timeout_short),
				RSRC_CONF,
				"Timeout for short duration HTTP calls (registry/discovery)."),
		AP_INIT_TAKE1("OIDCStateTimeout", oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, state_timeout),
				RSRC_CONF,
				"Time to live in seconds for state parameter (cq. interval in which the authorization request and the corresponding response need to be completed)."),

		AP_INIT_TAKE1("OIDCMetadataDir", oidc_set_dir_slot,
				(void*)APR_OFFSETOF(oidc_cfg, metadata_dir),
				RSRC_CONF,
				"Directory that contains provider and client metadata files."),
		AP_INIT_TAKE1("OIDCSessionType", oidc_set_session_type,
				(void*)APR_OFFSETOF(oidc_cfg, session_type),
				RSRC_CONF,
				"OpenID Connect session storage type (Apache 2.0/2.2 only). Must be one of \"file\" or \"cookie\"."),
		AP_INIT_FLAG("OIDCScrubRequestHeaders",
				oidc_set_flag_slot,
				(void *) APR_OFFSETOF(oidc_cfg, scrub_request_headers),
				RSRC_CONF,
				"Scrub user name and claim headers from the user's request."),

		AP_INIT_TAKE1("OIDCAuthNHeader", ap_set_string_slot,
				(void *) APR_OFFSETOF(oidc_dir_cfg, authn_header),
				ACCESS_CONF|OR_AUTHCFG,
				"Specify the HTTP header variable to set with the name of the authenticated user. By default no headers are added."),
		AP_INIT_TAKE1("OIDCCookiePath", ap_set_string_slot,
				(void *) APR_OFFSETOF(oidc_dir_cfg, cookie_path),
				ACCESS_CONF|OR_AUTHCFG,
				"Define the cookie path for the session cookie."),
		AP_INIT_TAKE1("OIDCCookie", ap_set_string_slot,
				(void *) APR_OFFSETOF(oidc_dir_cfg, cookie),
				ACCESS_CONF|OR_AUTHCFG,
				"Define the cookie name for the session cookie."),

		AP_INIT_TAKE1("OIDCCacheType", oidc_set_cache_type,
				(void*)APR_OFFSETOF(oidc_cfg, cache), RSRC_CONF,
				"Cache type; must be one of \"file\", \"memcache\" or \"shm\"."),

		AP_INIT_TAKE1("OIDCCacheDir", oidc_set_dir_slot,
				(void*)APR_OFFSETOF(oidc_cfg, cache_file_dir),
				RSRC_CONF,
				"Directory used for file-based caching."),
		AP_INIT_TAKE1("OIDCMemCacheServers",
				oidc_set_string_slot,
				(void*)APR_OFFSETOF(oidc_cfg, cache_memcache_servers),
				RSRC_CONF,
				"Memcache servers used for caching (space separated list of <hostname>[:<port>] tuples)"),
		AP_INIT_TAKE1("OIDCCacheShmMax", oidc_set_int_slot,
				(void*)APR_OFFSETOF(oidc_cfg, cache_shm_size_max),
				RSRC_CONF,
				"Maximum number of cache entries to use for \"shm\" caching."),

		{ NULL }
};
