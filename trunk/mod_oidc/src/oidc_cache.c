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
 * mem_cache-like interface and semantics (string keys/values) using a storage backend
 *
 * @Author: Hans Zandbelt - hans.zandbelt@gmail.com
 */

#include "mod_oidc.h"

extern module AP_MODULE_DECLARE_DATA oidc_module;

/*
 * get a value for the specified key from the cache
 */
apr_byte_t oidc_cache_get(request_rec *r, const char *key, const char **value) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &oidc_module);
	switch (cfg->cache_type) {
		case OIDC_CACHE_TYPE_FILE:
			return oidc_cache_file_get(r, key, value);
			break;
		case OIDC_CACHE_TYPE_MEMCACHE:
			return oidc_cache_memcache_get(r, key, value);
			break;
		case OIDC_CACHE_TYPE_SHM:
			return oidc_cache_shm_get(r, key, value);
			break;
		default:
			return FALSE;
	}
}

/*
 * write a value for the specified key to the cache
 */
apr_byte_t oidc_cache_set(request_rec *r, const char *key, const char *value, apr_time_t expiry) {
	oidc_cfg *cfg = ap_get_module_config(r->server->module_config, &oidc_module);
	switch (cfg->cache_type) {
		case OIDC_CACHE_TYPE_FILE:
			return oidc_cache_file_set(r, key, value, expiry);
			break;
		case OIDC_CACHE_TYPE_MEMCACHE:
			return oidc_cache_memcache_set(r, key, value, expiry);
			break;
		case OIDC_CACHE_TYPE_SHM:
			return oidc_cache_shm_set(r, key, value, expiry);
			break;
		default:
			return FALSE;
	}
}
