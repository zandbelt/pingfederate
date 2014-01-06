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
 * based on http://saju.net.in/code/misc/openssl_aes.c.txt
 *
 * @Author: Hans Zandbelt - hzandbelt@pingidentity.com
 */

#include <httpd.h>
#include <http_config.h>
#include <http_log.h>
#include <http_request.h>

#include <openssl/aes.h>

#include "mod_oidc.h"

/* initialize the crypt context in the server configuration record; the passphrase is set already */
apr_status_t oidc_crypto_init(oidc_cfg *cfg, server_rec *s) {

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
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "oidc_crypto_init: key size must be 256 bits!");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* initialize the encoding context */
	EVP_CIPHER_CTX_init(&cfg->e_ctx);
	if (!EVP_EncryptInit_ex(&cfg->e_ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "oidc_crypto_init: EVP_EncryptInit_ex on the encrypt context failed!");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	/* initialize the decoding context */
	EVP_CIPHER_CTX_init(&cfg->d_ctx);
	if (!EVP_DecryptInit_ex(&cfg->d_ctx, EVP_aes_256_cbc(), NULL, key, iv)) {
		ap_log_error(APLOG_MARK, APLOG_ERR, 0, s, "oidc_crypto_init: EVP_EncryptInit_ex on the decrypt context failed!");
		return HTTP_INTERNAL_SERVER_ERROR;
	}

	return APR_SUCCESS;
}

/* encrypt plaintext */
unsigned char *oidc_crypto_aes_encrypt(request_rec *r, EVP_CIPHER_CTX *e, unsigned char *plaintext, int *len) {

	/* max ciphertext len for a n bytes of plaintext is n + AES_BLOCK_SIZE -1 bytes */
	int c_len = *len + AES_BLOCK_SIZE, f_len = 0;
	unsigned char *ciphertext = apr_palloc(r->pool, c_len);

	/* allows reusing of 'e' for multiple encryption cycles */
	if (!EVP_EncryptInit_ex(e, NULL, NULL, NULL, NULL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_crypto_aes_encrypt: EVP_EncryptInit_ex failed!");
		return NULL;
	}

	/* update ciphertext, c_len is filled with the length of ciphertext generated, len is the size of plaintext in bytes */
	if (!EVP_EncryptUpdate(e, ciphertext, &c_len, plaintext, *len)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_crypto_aes_encrypt: EVP_EncryptUpdate failed!");
		return NULL;
	}

	/* update ciphertext with the final remaining bytes */
	if (!EVP_EncryptFinal_ex(e, ciphertext+c_len, &f_len)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_crypto_aes_encrypt: EVP_EncryptFinal_ex failed!");
		return NULL;
	}

	*len = c_len + f_len;

	return ciphertext;
}

/* decrypt ciphertext */
unsigned char *oidc_crypto_aes_decrypt(request_rec *r, EVP_CIPHER_CTX *e, unsigned char *ciphertext, int *len) {

	/* because we have padding ON, we must allocate an extra cipher block size of memory */
	int p_len = *len, f_len = 0;
	unsigned char *plaintext = apr_palloc(r->pool, p_len + AES_BLOCK_SIZE);

	/* allows reusing of 'e' for multiple encryption cycles */
	if (!EVP_DecryptInit_ex(e, NULL, NULL, NULL, NULL)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_crypto_aes_decrypt: EVP_DecryptInit_ex failed!");
		return NULL;
	}

	/* update plaintext, p_len is filled with the length of plaintext generated, len is the size of cyphertext in bytes */
	if (!EVP_DecryptUpdate(e, plaintext, &p_len, ciphertext, *len)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_crypto_aes_decrypt: EVP_DecryptUpdate failed!");
		return NULL;
	}

	/* update plaintext with the final remaining bytes */
	if (!EVP_DecryptFinal_ex(e, plaintext+p_len, &f_len)) {
		ap_log_rerror(APLOG_MARK, APLOG_ERR, 0, r, "oidc_crypto_aes_decrypt: EVP_DecryptFinal_ex failed!");
		return NULL;
	}

	*len = p_len + f_len;

	return plaintext;
}
