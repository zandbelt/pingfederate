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

#define OIDC_DEFAULT_SSL_VALIDATE_SERVER 1
#define OIDC_DEFAULT_ENDPOINT_AUTH "client_secret_basic"
#define OIDC_DEFAULT_SCOPE "openid"
#define OIDC_DEFAULT_ATTRIBUTE_DELIMITER ","
#define OIDC_DEFAULT_ATTRIBUTE_PREFIX "OIDC_ATTR_"

#define OIDC_DEFAULT_COOKIE "mod-oidc"
#define OIDC_DEFAULT_AUTHN_HEADER NULL
#define OIDC_DEFAULT_SCRUB_REQUEST_HEADERS NULL
#define OIDC_DEFAULT_DIR_SCOPE NULL

extern module AP_MODULE_DECLARE_DATA oidc_module;

const char *oidc_set_flag_slot(cmd_parms *cmd, void *struct_ptr, int arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(cmd->server->module_config, &oidc_module);
    return ap_set_flag_slot(cmd, cfg, arg);
}

const char *oidc_set_string_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(cmd->server->module_config, &oidc_module);
	//ap_log_error(APLOG_MARK, OIDC_DEBUG, 0, cmd->server, "oidc_set_string_slot: set value: %s", arg);
	return ap_set_string_slot(cmd, cfg, arg);
}

const char *oidc_set_url(apr_pool_t *pool, apr_uri_t *uri, const char *url) {
	if (url == NULL) {
		memset(uri, '\0', sizeof(apr_uri_t));
		return NULL;
	}
	if (apr_uri_parse(pool, url, uri) != APR_SUCCESS) {
		return apr_psprintf(pool, "oidc_set_url: URL '%s' could not be parsed!", url);
	}
	if (uri->port == 0) uri->port = apr_uri_port_of_scheme(uri->scheme);
	if (uri->hostname == NULL) return apr_psprintf(pool, "oidc_set_url: hostname in URL '%s' parsed to NULL!", url);
	return NULL;
}
/*
const char *oidc_set_uri_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(cmd->server->module_config, &oidc_module);
	int offset = (int)(long)cmd->info;
	apr_uri_t *p = (apr_uri_t *)((unsigned char *)cfg + offset);
	return oidc_set_url(cmd->pool, p, arg);
}
*/

// TODO: it's not really a syntax error... (could be fixed at runtime but then we'd have to restart the server)
const char *oidc_set_metadata_dir(cmd_parms *cmd, void *ptr, const char *arg) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(cmd->server->module_config, &oidc_module);
	if (oidc_metadata_dir_check(cmd->pool, cmd->server, arg) != APR_SUCCESS)
		return "OIDCMetadataDir contained a value that could not be verified as an accessible directory";
	return ap_set_string_slot(cmd, cfg, arg);
}

const char *oidc_set_cookie_domain(cmd_parms *cmd, void *ptr, const char *value) {
	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(cmd->server->module_config, &oidc_module);
	size_t sz, limit;
	char d;
	limit = strlen(value);
	for(sz = 0; sz < limit; sz++) {
		d = value[sz];
		if ( (d < '0' || d > '9') &&
				(d < 'a' || d > 'z') &&
				(d < 'A' || d > 'Z') &&
				d != '.' && d != '-') {
			return(apr_psprintf(cmd->pool, "oidc_set_cookie_domain: invalid character (%c) in OIDCCookieDomain", d));
		}
	}
	cfg->cookie_domain = apr_pstrdup(cmd->pool, value);
	return NULL;
}

const char *oidc_set_endpoint_auth_slot(cmd_parms *cmd, void *struct_ptr, const char *arg) {

	oidc_cfg *cfg = (oidc_cfg *) ap_get_module_config(cmd->server->module_config, &oidc_module);

	if ((apr_strnatcmp(arg, "client_secret_post") == 0)
		||
		(apr_strnatcmp(arg, "client_secret_basic") == 0) ) {

		return ap_set_string_slot(cmd, cfg, arg);

	}

	return "parameter must be 'client_secret_post' or 'client_secret_basic'";
}

char *oidc_get_endpoint(request_rec *r, apr_uri_t *url, const char *s) {
	apr_uri_t test;
	memset(&test, '\0', sizeof(apr_uri_t));
	if (memcmp(url, &test, sizeof(apr_uri_t)) == 0) {
		if (s != NULL) ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_get_endpoint: %s null (not set?)", s);
		return NULL;
	}
	return (apr_uri_unparse(r->pool, url, 0));
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
		if (strncmp(d->dir_scope, requestPath, strlen(d->dir_scope)) == 0)
			rv = d->dir_scope;
		else {
			ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_get_dir_scope: OIDCDirScope (%s) not a substring of request path, using request path (%s) for cookie", d->dir_scope, requestPath);
			rv = requestPath;
		}
	} else {
			rv = requestPath;
	}
	return (rv);
}

void *oidc_create_server_config(apr_pool_t *pool, server_rec *svr) {
	oidc_cfg *c = apr_pcalloc(pool, sizeof(oidc_cfg));

	c->merged = FALSE;

	c->redirect_uri = NULL;

	c->provider.ssl_validate_server = OIDC_DEFAULT_SSL_VALIDATE_SERVER;
	c->provider.issuer = NULL;
	c->provider.authorization_endpoint_url = NULL;
	c->provider.token_endpoint_url = NULL;
	c->provider.token_endpoint_auth = OIDC_DEFAULT_ENDPOINT_AUTH;
	c->provider.userinfo_endpoint_url = NULL;
	c->provider.client_id  = NULL;
	c->provider.client_secret = NULL;
	c->provider.scope = OIDC_DEFAULT_SCOPE;

	c->oauth.ssl_validate_server = OIDC_DEFAULT_SSL_VALIDATE_SERVER;
	c->oauth.client_id = NULL;
	c->oauth.client_secret = NULL;
	c->oauth.validate_endpoint_url = NULL;
	c->oauth.validate_endpoint_auth = OIDC_DEFAULT_ENDPOINT_AUTH;

	c->cache_dir = NULL;
	c->metadata_dir = NULL;

	c->cookie_domain = NULL;
	c->attribute_delimiter = OIDC_DEFAULT_ATTRIBUTE_DELIMITER;
	c->attribute_prefix = OIDC_DEFAULT_ATTRIBUTE_PREFIX;
	c->crypto_passphrase = NULL;

	return c;
}

void *oidc_merge_server_config(apr_pool_t *pool, void *BASE, void *ADD) {
	oidc_cfg *c = apr_pcalloc(pool, sizeof(oidc_cfg));
	oidc_cfg *base = BASE;
	oidc_cfg *add = ADD;

	c->merged = TRUE;

	c->redirect_uri = add->redirect_uri != NULL ? add->redirect_uri : base->redirect_uri;

	c->provider.ssl_validate_server = add->provider.ssl_validate_server != OIDC_DEFAULT_SSL_VALIDATE_SERVER ? add->provider.ssl_validate_server : base->provider.ssl_validate_server;
	c->provider.issuer = add->provider.issuer != NULL ? add->provider.issuer : base->provider.issuer;
	c->provider.authorization_endpoint_url = add->provider.authorization_endpoint_url != NULL ? add->provider.authorization_endpoint_url : base->provider.authorization_endpoint_url;
	c->provider.token_endpoint_url = add->provider.token_endpoint_url != NULL ? add->provider.token_endpoint_url : base->provider.token_endpoint_url;
	c->provider.token_endpoint_auth = add->provider.token_endpoint_auth != OIDC_DEFAULT_ENDPOINT_AUTH ? add->provider.token_endpoint_auth : base->provider.token_endpoint_auth;
	c->provider.userinfo_endpoint_url = add->provider.userinfo_endpoint_url != NULL ? add->provider.userinfo_endpoint_url : base->provider.userinfo_endpoint_url;
	c->provider.client_id = add->provider.client_id != NULL ? add->provider.client_id : base->provider.client_id;
	c->provider.client_secret = add->provider.client_secret != NULL ? add->provider.client_secret : base->provider.client_secret;
	c->provider.scope = add->provider.scope != OIDC_DEFAULT_SCOPE ? add->provider.scope : base->provider.scope;

	c->oauth.ssl_validate_server = add->oauth.ssl_validate_server != OIDC_DEFAULT_SSL_VALIDATE_SERVER ? add->oauth.ssl_validate_server : base->oauth.ssl_validate_server;
	c->oauth.client_id = add->oauth.client_id != NULL ? add->oauth.client_id : base->oauth.client_id;
	c->oauth.client_secret = add->oauth.client_secret != NULL ? add->oauth.client_secret : base->oauth.client_secret;
	c->oauth.validate_endpoint_url = add->oauth.validate_endpoint_url != NULL ? add->oauth.validate_endpoint_url : base->oauth.validate_endpoint_url;
	c->oauth.validate_endpoint_auth = add->oauth.validate_endpoint_auth != OIDC_DEFAULT_ENDPOINT_AUTH ? add->oauth.validate_endpoint_auth : base->oauth.validate_endpoint_auth;

	c->cache_dir = add->cache_dir != NULL ? add->cache_dir : base->cache_dir;
	c->metadata_dir = add->metadata_dir != NULL ? add->metadata_dir : base->metadata_dir;

	c->cookie_domain = add->cookie_domain != NULL ? add->cookie_domain : base->cookie_domain;
	c->attribute_delimiter = add->attribute_delimiter != OIDC_DEFAULT_ATTRIBUTE_DELIMITER ? add->attribute_delimiter : base->attribute_delimiter;
	c->attribute_prefix = add->attribute_prefix != OIDC_DEFAULT_ATTRIBUTE_PREFIX ? add->attribute_prefix : base->attribute_prefix;
	c->crypto_passphrase = add->crypto_passphrase != NULL ? add->crypto_passphrase : base->crypto_passphrase;

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
	if (add->dir_scope != NULL && apr_strnatcasecmp(add->dir_scope, "Off") == 0)
		c->dir_scope = NULL;
	c->authn_header = (add->authn_header != OIDC_DEFAULT_AUTHN_HEADER ?
		add->authn_header : base->authn_header);
	if (add->authn_header != NULL && apr_strnatcasecmp(add->authn_header, "Off") == 0)
		c->authn_header = NULL;
	c->scrub_request_headers = (add->scrub_request_headers != OIDC_DEFAULT_SCRUB_REQUEST_HEADERS ?
		 add->scrub_request_headers :
		 base->scrub_request_headers);
	if (add->scrub_request_headers != NULL && apr_strnatcasecmp(add->scrub_request_headers, "Off") == 0)
		c->scrub_request_headers = NULL;
	return(c);
}

#if defined(OPENSSL_THREADS) && APR_HAS_THREADS

static apr_thread_mutex_t **ssl_locks;
static int ssl_num_locks;

static void oidc_ssl_locking_callback(int mode, int type, const char *file, int line) {
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
static void oidc_ssl_id_callback(CRYPTO_THREADID *id)
{
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

int oidc_post_config(apr_pool_t *pool, apr_pool_t *p1, apr_pool_t *p2, server_rec *s) {
	const char *userdata_key = "auth_oidc_init";
	void *data = NULL;
	int i;

	ap_log_error(APLOG_MARK, OIDC_DEBUG, 0, s, "oidc_post_config: called for (%pp)", s);

	/* Since the post_config hook is invoked twice (once
	 * for 'sanity checking' of the config and once for
	 * the actual server launch, we have to use a hack
	 * to not run twice
	 */
	apr_pool_userdata_get(&data, userdata_key, s->process->pool);
	if (data == NULL) {
		apr_pool_userdata_set((const void *)1, userdata_key, apr_pool_cleanup_null, s->process->pool);
		return OK;
	}
		
	curl_global_init(CURL_GLOBAL_ALL);

#if (defined(OPENSSL_THREADS) && APR_HAS_THREADS)
	ssl_num_locks = CRYPTO_num_locks();
	ssl_locks = apr_pcalloc(s->process->pool, ssl_num_locks * sizeof(*ssl_locks));

	for(i = 0; i < ssl_num_locks; i++)
		apr_thread_mutex_create(&(ssl_locks[i]), APR_THREAD_MUTEX_DEFAULT, s->process->pool);

#ifdef OPENSSL_NO_THREADID
	if (CRYPTO_get_locking_callback() == NULL && CRYPTO_get_id_callback() == NULL) {
		CRYPTO_set_locking_callback(oidc_ssl_locking_callback);
		CRYPTO_set_id_callback(oidc_ssl_id_callback);
	}
#else
	if (CRYPTO_get_locking_callback() == NULL && CRYPTO_THREADID_get_callback() == NULL) {
		CRYPTO_set_locking_callback(oidc_ssl_locking_callback);
		CRYPTO_THREADID_set_callback(oidc_ssl_id_callback);
	}
#endif /* OPENSSL_NO_THREADID */
#endif /* defined(OPENSSL_THREADS) && APR_HAS_THREADS */
	apr_pool_cleanup_register(pool, s, oidc_cleanup, apr_pool_cleanup_null);

	// TODO: maybe there's a different way to initialize post-config stuff per server rec?
	server_rec *sp = s;
	apr_status_t rc = APR_SUCCESS;
	while (sp != NULL) {
		if ((rc = oidc_crypto_init(pool, sp)) != APR_SUCCESS) return rc;
		if ((rc = oidc_cache_init(pool, sp)) != APR_SUCCESS) return rc;
		if ((rc = oidc_session_init(pool, sp)) != APR_SUCCESS) return rc;
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
//	if (!merged_vhost_configs_exist(s)) {
		/* nothing merged, only check the base vhost */
//		return check_vhost_config(pool, s);
//	}

	return OK;
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
static const authz_provider authz_oidc_provider = {
    &oidc_authz_checker,
    NULL,
};
#endif

void oidc_register_hooks(apr_pool_t *pool) {
	static const char *const authzSucc[] = { "mod_authz_user.c", NULL };
	ap_hook_post_config(oidc_post_config, NULL, NULL, APR_HOOK_LAST);
#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
	ap_hook_check_authn(oidc_check_user_id, NULL, NULL, APR_HOOK_MIDDLE, AP_AUTH_INTERNAL_PER_CONF);
	ap_register_auth_provider(pool, AUTHZ_PROVIDER_GROUP, "attribute", "0", &authz_oidc_provider, AP_AUTH_INTERNAL_PER_CONF);
#else
	ap_hook_check_user_id(oidc_check_user_id, NULL, NULL, APR_HOOK_MIDDLE);
	ap_hook_auth_checker(oidc_auth_checker, NULL, authzSucc, APR_HOOK_MIDDLE);
#endif
}
