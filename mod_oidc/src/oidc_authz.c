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
 * mostly copied from mod_auth_cas
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <http_core.h>
#include <http_log.h>
#include <http_protocol.h>

#include "mod_oidc.h"

#define OIDC_AUTHZ_CLAIM_MATCH 0
#define OIDC_AUTHZ_CLAIM_NO_MATCH 1

#define OIDC_REQUIRE_NAME "claim"

static int oidc_authz_match_claim(const char *const attr_spec, const apr_json_value_t *const claims, struct request_rec *r) {

	apr_hash_index_t *hi;
	const void *key;
	apr_ssize_t klen;
	void *hval;

	if (claims == NULL) return OIDC_AUTHZ_CLAIM_NO_MATCH;

	/* Loop over all of the user claims */
	for (hi = apr_hash_first(r->pool, claims->value.object); hi; hi = apr_hash_next(hi)) {
        apr_hash_this(hi, &key, &klen, &hval);

		const char *attr_c = (const char *)key;
		const char *spec_c = attr_spec;

		/* Walk both strings until we get to the end of either or we
		 * find a differing character */
		while ((*attr_c) &&
		       (*spec_c) &&
		       (*attr_c) == (*spec_c)) {
			attr_c++;
			spec_c++;
		}


		/* The match is a success if we walked the whole claim
		 * name and the attr_spec is at a colon. */
		if (!(*attr_c) && (*spec_c) == ':') {
			const apr_json_value_t *val;

			val = ((apr_json_value_t *)hval);

			/* Skip the colon */
			spec_c++;

			if (val->type == APR_JSON_STRING) {

				if (apr_strnatcmp(val->value.string.p, spec_c) == 0) {
					return OIDC_AUTHZ_CLAIM_MATCH;
				}

			} else if (val->type == APR_JSON_BOOLEAN) {

				if (apr_strnatcmp(val->value.boolean ? "true" : "false", spec_c) == 0) {
					return OIDC_AUTHZ_CLAIM_MATCH;
				}

			} else if (val->type == APR_JSON_ARRAY) {

				/* Compare the claim values */
				int i = 0;
				for (i = 0; i < val->value.array->nelts; i++) {

					apr_json_value_t *elem = APR_ARRAY_IDX(val->value.array, i, apr_json_value_t *);

					if (elem->type == APR_JSON_STRING) {

						/* Approximately compare the claim value (ignoring
						 * whitespace). At this point, spec_c points to the
						 * NULL-terminated value pattern. */
						if (apr_strnatcmp(elem->value.string.p, spec_c) == 0) {
							return OIDC_AUTHZ_CLAIM_MATCH;
						}

					} else if  (elem->type == APR_JSON_BOOLEAN) {

						if (apr_strnatcmp(elem->value.boolean ? "true" : "false", spec_c) == 0) {
							return OIDC_AUTHZ_CLAIM_MATCH;
						}

					} else {

						ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_authz_match_claim: unhandled in-array JSON object type [%d] for key \"%s\"", elem->type, (const char *)key);
						continue;
					}
				}

			} else {
				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_authz_match_claim: unhandled JSON object type [%d] for key \"%s\"", val->type, (const char *)key);
				continue;
			}

		}
		/* The match is a success is we walked the whole claim
		 * name and the attr_spec is a tilde (denotes a PCRE match). */
//		else if (!(*attr_c) && (*spec_c) == '~') {
//			const apr_json_value_t *val;
//			const char *errorptr;
//			int erroffset;
//			pcre *preg;
//
//			/* Skip the tilde */
//			spec_c++;
//
//			/* Set up the regex */
//			preg = pcre_compile(spec_c, 0, &errorptr, &erroffset, NULL);
//			if (NULL == preg) {
//				ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "Pattern [%s] is not a valid regular expression", spec_c);
//				continue;
//			}
//
//			/* Compare the claim values */
//			val = attr->values;
//			for ( ; val; val = val->next) {
//				/* PCRE-compare the claim value. At this point, spec_c
//				 * points to the NULL-terminated value pattern. */
//				if (0 == pcre_exec(preg, NULL, val->value, (int)strlen(val->value), 0, 0, NULL, 0)) {
//					pcre_free(preg);
//					return PING_OAUTH20_ATTR_MATCH;
//				}
//			}
//
//			pcre_free(preg);
//		}
	}
	return OIDC_AUTHZ_CLAIM_NO_MATCH;
}

int oidc_authz_worker(request_rec *r, const apr_json_value_t *const attrs, const require_line *const reqs, int nelts) {
	const int m = r->method_number;
	const char *token;
	const char *requirement;
	int i;
	int have_oauthattr = 0;
	int count_oauthattr = 0;

	// Q: why don't we use ap_some_auth_required here?? performance?

	/* Go through applicable Require directives */
	for (i = 0; i < nelts; ++i) {
		/* Ignore this Require if it's in a <Limit> section
		 * that exclude this method
		 */

		if (!(reqs[i].method_mask & (AP_METHOD_BIT << m))) {
			continue;
		}

		/* ignore if it's not a "Require claim ..." */
		requirement = reqs[i].requirement;

		token = ap_getword_white(r->pool, &requirement);

		if (apr_strnatcasecmp(token, OIDC_REQUIRE_NAME) != 0) {
			continue;
		}

		/* OK, we have a "Require claim" to satisfy */
		have_oauthattr = 1;

		/* If we have an applicable claim, but no
		 * claims were sent in the request, then we can
		 * just stop looking here, because it's not
		 * satisfiable. The code after this loop will give the
		 * appropriate response. */
		if (!attrs) {
			break;
		}

		/* Iterate over the claim specification strings in this
		 * require directive searching for a specification that
		 * matches one of the claims. */
		while (*requirement) {
			token = ap_getword_conf(r->pool, &requirement);
			count_oauthattr++;

			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				     "oidc_authz_worker: evaluating claim specification: %s",
				     token);

			if (oidc_authz_match_claim(token, attrs, r) ==
					OIDC_AUTHZ_CLAIM_MATCH) {

				/* If *any* claim matches, then
				 * authorization has succeeded and all
				 * of the others are ignored. */
				ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
					      "oidc_authz_worker: require claim "
					      "'%s' matched", token);
				return OK;
			}
		}
	}

	/* If there weren't any "Require claim" directives,
	 * we're irrelevant.
	 */
	if (!have_oauthattr) {
		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
			      "oidc_authz_worker: no claim statements found, not performing authz.");
		return DECLINED;
	}
	/* If there was a "Require claim", but no actual claims,
	 * that's cause to warn the admin of an iffy configuration.
	 */
	if (count_oauthattr == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
			      "oidc_authz_worker: 'require claim' missing specification(s) in configuration. Declining.");
		return DECLINED;
	}

	/* OK, our decision is final and binding */
	ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
		      "oidc_authz_worker: authorization denied for client session");

	ap_note_auth_failure(r);

	return HTTP_UNAUTHORIZED;
}

#if MODULE_MAGIC_NUMBER_MAJOR >= 20100714
authz_status oidc_authz_worker24(request_rec *r, const apr_json_value_t * const attrs,
		const char *require_args) {

	int count_oauthattr = 0;
	const char *t, *w;

	if (r->user == NULL) return AUTHZ_DENIED_NO_USER;

	if (!attrs)
		return AUTHZ_DENIED;

	t = require_args;
	while ((w = ap_getword_conf(r->pool, &t)) && w[0]) {

		count_oauthattr++;

		ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
				"oidc_authz_worker24: evaluating claim specification: %s",
				w);

		if (oidc_authz_match_claim(w, attrs, r) == OIDC_AUTHZ_CLAIM_MATCH) {

			ap_log_rerror(APLOG_MARK, OIDC_DEBUG, 0, r,
					"oidc_authz_worker24: require claim "
							"'%s' matched", w);
			return AUTHZ_GRANTED;
		}
	}

	if (count_oauthattr == 0) {
		ap_log_rerror(APLOG_MARK, APLOG_WARNING, 0, r,
				"oidc_authz_worker24: 'require claim' missing specification(s) in configuration. Denying.");
	}

	return AUTHZ_DENIED;
}
#endif
