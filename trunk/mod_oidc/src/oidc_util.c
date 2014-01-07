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

//#include <stdio.h>
#include <curl/curl.h>

#include <apr_strings.h>
#include <apr_base64.h>
#include <apr_lib.h>

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>
#include "http_protocol.h"

#include "mod_oidc.h"

extern module AP_MODULE_DECLARE_DATA oidc_module;

// TODO: always padded now, do we need an option to remove the padding?
int oidc_base64url_encode(request_rec *r, char **dst, const char *src, int src_len) {
	if ( (src == NULL) || (src_len <= 0) ) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_base64url_encode: not encoding anything; src=NULL and/or src_len<1");
		return -1;
	}
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
	if (src == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_base64url_decode: not encoding anything; src=NULL");
		return -1;
	}
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
	unsigned char *crypted = oidc_crypto_aes_encrypt(r, c, (unsigned char *)src, &crypted_len);
	if (crypted == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_encrypt_base64url_encode_string: oidc_crypto_aes_encrypt failed");
		return -1;
	}
	return oidc_base64url_encode(r, dst, (const char *)crypted, crypted_len);
}

int oidc_base64url_decode_decrypt_string(request_rec *r, char **dst, const char *src) {
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);
	char *decbuf = NULL;
	int dec_len = oidc_base64url_decode(r, &decbuf, src, 0);
	if (dec_len <= 0) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_base64url_decode_decrypt_string: oidc_base64url_decode failed");
		return -1;
	}
	*dst = (char *)oidc_crypto_aes_decrypt(r, c, (unsigned char *)decbuf, &dec_len);
	if (*dst == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_base64url_decode_decrypt_string: oidc_crypto_aes_decrypt failed");
		return -1;
	}
	return dec_len;
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

char *oidc_url_encode(const request_rec *r, const char *str,
								const char *charsToEncode) {
	char *rv, *p;
	const char *q;
	size_t i, j, size, limit, newsz;
	char escaped = FALSE;

	if (str == NULL)
		return "";

	size = newsz = strlen(str);
	limit = strlen(charsToEncode);

	for(i = 0; i < size; i++) {
		for(j = 0; j < limit; j++) {
			if (str[i] == charsToEncode[j]) {
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
			if (*q == charsToEncode[i]) {
				sprintf(p, "%%%x", charsToEncode[i]);
				p+= 3;
				escaped = TRUE;
				break;
			}
		}
		if (escaped == FALSE) {
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
		apr_table_get(r->headers_in, "Host"),
		port_str, r->uri,
		(r->args != NULL && *r->args != '\0' ? "?" : ""),
		r->args, NULL);
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_get_current_url: current URL '%s'", url);
	return url;
}

#define OIDC_CURL_MAX_RESPONSE_SIZE 65536

typedef struct oidc_curl_buffer {
	char buf[OIDC_CURL_MAX_RESPONSE_SIZE];
	size_t written;
} oidc_curl_buffer;

size_t oidc_curl_write(const void *ptr, size_t size, size_t nmemb, void *stream) {
	oidc_curl_buffer *curlBuffer = (oidc_curl_buffer *) stream;

	if ((nmemb*size) + curlBuffer->written >= OIDC_CURL_MAX_RESPONSE_SIZE)
		return 0;

	memcpy((curlBuffer->buf + curlBuffer->written), ptr, (nmemb*size));
	curlBuffer->written += (nmemb*size);

	return (nmemb*size);
}

// TODO: solve a spurious SSL error against PingFederate 7.1.0-R2, multi-process/threading issue?
//
//       oidc_http_call: curl_easy_perform() failed (Unknown SSL protocol error in connection to <authorization-host> )
//
//       happens on Ubuntu 12.04 and 13.10 but not on Mac OS X macports (although it could still be a timing/server issue)
//       all environments non-threaded, but pre-fork MPM
//
//       OK: Mac OS X 10.9.1, MacPorts 2.2.0, Apache 2.2.25, OpenSSL 1.0.1e, Curl 7.32.0
//       ERR: Ubuntu 13.10: Apache 2.4.6,  OpenSSL 1.0.1e, Curl 7.32.0
//       ERR: Ubuntu 12.04: Apache 2.2.22, OpenSSL 1.0.1,  Curl 7.22.0
char *oidc_http_call(request_rec *r, const char *url, const char *postfields, const char *basic_auth, const char *bearer_token, int ssl_validate_server) {
	char curlError[CURL_ERROR_SIZE];
	oidc_curl_buffer curlBuffer;
	CURL *curl;
	char *rv = NULL;

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_http_call: entering, url=%s, postfields=%s, basic_auth=%s, bearer_token=%s, ssl_validate_server=%d", url, postfields, basic_auth, bearer_token, ssl_validate_server);

	curl = curl_easy_init();
	if (curl == NULL) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_http_call: curl_easy_init() error");
		return NULL;
	}

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

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, (ssl_validate_server != FALSE ? 1L : 0L));
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, (ssl_validate_server != FALSE ? 2L : 0L));

	curl_easy_setopt(curl, CURLOPT_USERAGENT, "mod_oidc 1.0");

	curl_easy_setopt(curl, CURLOPT_URL, url);

	if (bearer_token != NULL) {
		struct curl_slist *headers = NULL;
		headers = curl_slist_append(headers, apr_psprintf(r->pool, "Authorization: Bearer %s", bearer_token));
		curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
	}

	if (basic_auth != NULL) {
		curl_easy_setopt(curl, CURLOPT_HTTPAUTH, CURLAUTH_BASIC);
		curl_easy_setopt(curl, CURLOPT_USERPWD, basic_auth);
	}

	if (postfields != NULL) {
		curl_easy_setopt(curl, CURLOPT_POSTFIELDS, postfields);
		// CURLOPT_POST needed at least to set: Content-Type: application/x-www-form-urlencoded
		curl_easy_setopt(curl, CURLOPT_POST, 1);
	}

	if (curl_easy_perform(curl) != CURLE_OK) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_http_call: curl_easy_perform() failed (%s)", curlError);
		goto out;
	}

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_http_call: response=%s", curlBuffer.buf);

	rv = apr_pstrndup(r->pool, curlBuffer.buf, strlen(curlBuffer.buf));

out:
	curl_easy_cleanup(curl);
	return rv;
}

void oidc_set_cookie(request_rec *r, char *cookieName, char *cookieValue) {

	char *headerString, *currentCookies;
	oidc_cfg *c = ap_get_module_config(r->server->module_config, &oidc_module);
	headerString = apr_psprintf(r->pool, "%s=%s%s;Path=%s%s%s", cookieName, cookieValue, ";Secure", oidc_url_encode(r, oidc_get_dir_scope(r), " "), (c->cookie_domain != NULL ? ";Domain=" : ""), (c->cookie_domain != NULL ? c->cookie_domain : ""));
	if (apr_strnatcmp(cookieValue, "") == 0) headerString = apr_psprintf(r->pool, "%s;expires=0;Max-Age=0", headerString);
	/* use r->err_headers_out so we always print our headers (even on 302 redirect) - headers_out only prints on 2xx responses */
	apr_table_add(r->err_headers_out, "Set-Cookie", headerString);
	if ((currentCookies = (char *) apr_table_get(r->headers_in, "Cookie")) == NULL)
		apr_table_add(r->headers_in, "Cookie", headerString);
	else
		apr_table_set(r->headers_in, "Cookie", (apr_pstrcat(r->pool, headerString, ";", currentCookies, NULL)));

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_set_cookie: adding outgoing header: Set-Cookie: %s", headerString);

	return;
}

char *oidc_get_cookie(request_rec *r, char *cookieName) {
	char *cookie, *tokenizerCtx, *rv = NULL;
	apr_byte_t cookieFound = FALSE;

	char *cookies = apr_pstrdup(r->pool, (char *) apr_table_get(r->headers_in, "Cookie"));
	if (cookies != NULL) {
		/* tokenize on ; to find the cookie we want */
		cookie = apr_strtok(cookies, ";", &tokenizerCtx);
		do {
			while (cookie != NULL && *cookie == ' ')
				cookie++;
			if (strncmp(cookie, cookieName, strlen(cookieName)) == 0) {
				cookieFound = TRUE;
				/* skip to the meat of the parameter (the value after the '=') */
				cookie += (strlen(cookieName)+1);
				rv = apr_pstrdup(r->pool, cookie);
			}
			cookie = apr_strtok(NULL, ";", &tokenizerCtx);
		/* no more parameters */
		if (cookie == NULL)
			break;
		} while (cookieFound == FALSE);
	}

	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_get_cookie: returning %s", rv);

	return rv;
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

apr_byte_t oidc_request_matches_url(request_rec *r, const char *url) {
	apr_uri_t uri;
	apr_uri_parse(r->pool, url, &uri);
	apr_byte_t rc = (apr_strnatcmp(r->parsed_uri.path, uri.path) == 0) ? TRUE : FALSE;
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r, "oidc_request_matches_url: comparing \"%s\"==\"%s\" (%d)", r->parsed_uri.path, uri.path, rc);
	return rc;
}

apr_byte_t oidc_request_has_parameter(request_rec *r, const char* param) {
	const char *option1 = apr_psprintf(r->pool, "%s=", param);
	const char *option2 = apr_psprintf(r->pool, "&%s=", param);
	return ( (strstr(r->args, option1) == r->args) || (strstr(r->args, option2) != NULL) );
}

// TODO: we should really check with ? and & and avoid any <bogus>code= stuff to trigger true
apr_byte_t oidc_get_request_parameter(request_rec *r, char *name, char **value) {
	char *tokenizer_ctx, *p, *args, *rv = NULL;
	const char *k_param = apr_psprintf(r->pool, "%s=", name);
	const size_t k_param_sz = strlen(k_param);

	*value = NULL;

	if (r->args == NULL || strlen(r->args) == 0) return FALSE;

	/* not sure why we do this, but better be safe than sorry */
	args = apr_pstrndup(r->pool, r->args, strlen(r->args));

	p = apr_strtok(args, "&", &tokenizer_ctx);
	do {
		if (p && strncmp(p, k_param, k_param_sz) == 0) {
			*value = apr_pstrdup(r->pool, p + k_param_sz);
			ap_unescape_url(*value);
		}
		p = apr_strtok(NULL, "&", &tokenizer_ctx);
	} while (p);

	return (*value != NULL ? TRUE : FALSE);
}

/*
 * printout a JSON string value
 */
static apr_byte_t oidc_util_json_string_print(request_rec *r, apr_json_value_t *result, const char *key, const char *log) {
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

/*
 * check a JSON object for "error" results and printout
 */
apr_byte_t oidc_util_check_json_error(request_rec *r, apr_json_value_t *json) {
	if (oidc_util_json_string_print(r, json, "error", "oidc_util_check_json_error") == TRUE) {
		oidc_util_json_string_print(r, json, "error_description", "oidc_util_check_json_error");
		return TRUE;
	}
	return FALSE;
}
