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

#ifndef _OIDC_CACHE_H_
#define _OIDC_CACHE_H_

typedef apr_byte_t (*oidc_cache_get_function)(request_rec *r, const char *key, const char **value);
typedef apr_byte_t (*oidc_cache_set_function)(request_rec *r, const char *key, const char *value, apr_time_t expiry);

typedef struct oidc_cache_t {
	oidc_cache_get_function get;
	oidc_cache_set_function set;
} oidc_cache_t;

/*
 * file
 */
extern oidc_cache_t oidc_cache_file;

/*
 * memcache
 */
extern oidc_cache_t oidc_cache_memcache;

const char * oidc_cache_memcache_init(cmd_parms *cmd, void *ptr, const char *arg);

/*
 * shared memory
 */
extern oidc_cache_t oidc_cache_shm;

typedef struct oidc_cache_cfg_shm_t {
	int cache_size_max;
	char *mutex_filename;
	apr_shm_t *shm;
	apr_global_mutex_t *mutex;
} oidc_cache_cfg_shm_t;

apr_byte_t oidc_cache_shm_init(server_rec *s);
void oic_cache_shm_child_init(apr_pool_t *p, server_rec *s);

#endif /* _OIDC_CACHE_H_ */
