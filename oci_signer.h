/*
 * Copyright (c) 2025 Riptides Labs, Inc.
 * SPDX-License-Identifier: MIT
 */

#ifndef __OCI_SIGNER_H
#define __OCI_SIGNER_H

/*
  Replace the standards header files with a single system-specific header file.
  Value must include quotes, for example `#define OCI_SYSTEM_HEADER "foo.h"
*/
#ifdef OCI_SYSTEM_HEADER
#include OCI_SYSTEM_HEADER
#else
#include <stdarg.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <strings.h>
#include <ctype.h>
#endif

#define OCI_SIGNER_OK 0
#define OCI_SIGNER_INVALID_INPUT_ERROR -1
#define OCI_SIGNER_AUTH_HEADER_BUFFER_OVERFLOW_ERROR -2
#define OCI_SIGNER_INVALID_HEADER_ERROR -3
#define OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR -4
#define OCI_SIGNER_SIGNING_HEADERS_BUFFER_OVERFLOW_ERROR -5
#define OCI_SIGNER_REQUEST_TARGET_BUFFER_OVERFLOW_ERROR -6

#define OCI_RSA_SIGN_ERROR_BASE -1000
#define OCI_BASE64_ENCODE_ERROR_BASE -2000


/*
 * Headers used in the signing process:
 * - date
 * - host
 * - x-date (if present, use instead of date)
 * - content-length
 * - content-type
 * - x-content-sha256
 */
#define OCI_SIGNER_MAX_NUM_HEADERS 6


/*
 * Maximum length for authorization header which includes:
 * - keyId
 * - algorithm
 * - signing headers
 * - signature
 */
#define OCI_SIGNER_AUTH_HEADER_MAX_LEN 4096

/*
 * Authorization header includes:
 * - keyId
 * - algorithm
 * - signing headers
 * - signature
 */

typedef struct oci_signer_str_s
{
  unsigned char *data;
  unsigned int len;
} oci_signer_str_t;

/* Binary data structure for non-string binary data like DER keys */
typedef struct oci_signer_binary_s
{
  unsigned char *data;
  unsigned int len;
} oci_signer_binary_t;

typedef struct oci_signer_kv_s
{
  oci_signer_str_t key;
  oci_signer_str_t value;
} oci_signer_kv_t;

oci_signer_str_t oci_signer_string(const unsigned char *cstr);

int oci_signer_strcmp(oci_signer_str_t *str1, oci_signer_str_t *str2);

int oci_signer_empty_str(oci_signer_str_t *str);

/** @brief Check if a binary data is empty
 *
 * @param[in] bin  Pointer to a binary data
 * @return 1 if binary data is empty, 0 otherwise
 */
int oci_signer_empty_binary(oci_signer_binary_t *bin);

/** @brief Determine if body should be excluded from signing
 *
 * @param[in] method HTTP method
 * @param[in] host   Host header value
 * @param[in] uri    Request URI (path and query)
 * @return true if body should be excluded, false otherwise
 */
bool oci_signer_should_exclude_body_signing(oci_signer_str_t *method, oci_signer_str_t *host, oci_signer_str_t *uri);

typedef oci_signer_kv_t oci_signer_header_t;

typedef struct oci_signer_params_s
{
  /* OCI credential parameters */
  oci_signer_binary_t private_key;  /* RSA private key in DER format */
  oci_signer_str_t key_id;          /* OCI key ID in format: tenancy/user/fingerprint or ST$<user principal session token> */

  /* HTTP request parameters */
  oci_signer_str_t method; /* HTTP method, e.g. "GET", "POST" */
  oci_signer_str_t uri;   /* Request URI (path and query), e.g. "/20160918/instances" */
  oci_signer_str_t payload; /* Request payload (body), can be empty for GET requests */

  /* Array of signing headers as key-value pairs.
  * host - required
  * date - if not present, it defaults the current date and time will be used
  * x-date - if present, will be used instead of date
  * content-length - if not present it defaults to the length of the payload for requests with body
  * content-type - if not present it defaults to application/json for requests with body
  * x-content-sha256 - if not present it default to sha256 of payload for requests with body
  */
  oci_signer_kv_t headers[OCI_SIGNER_MAX_NUM_HEADERS];
  unsigned int num_headers;


  /* SHA256 function returns the sha256 digest of the input data
  * data - pointer to the input data
  * len  - length of the input data
  * out  - pointer to the output buffer for the SHA-256 digest
  * Returns a pointer to the output buffer on success, or NULL on failure
  */
  unsigned char *(*sha256)(const unsigned char *data, size_t len, unsigned char *out);


  /* RSA Sign function signs a SHA-256 digest using a PKCS#1 RSA private key
  * sha256_digest_data - pointer to 32-byte SHA-256 digest
  * sha256_digest_len  - must be 32
  * pkcs1_key_data     - PKCS#1 private key DER in memory
  * pkcs1_key_len      - length of the key
  * sig                - output buffer for the signature
  * sig_len            - input: buffer size, output: actual signature length
  */
  int (*rsa_sign_sha256)(const unsigned char *sha256_digest_data, size_t sha256_digest_len,
             const unsigned char *pkcs1_key_data, size_t pkcs1_key_len,
             unsigned char *sig, size_t *sig_len);

  /* Base64 encode function 
  * in      - input buffer
  * in_len  - length of input buffer
  * out     - output buffer
  * out_len - in: size of output buffer, out: actual length of encoded data
  * Returns 0 on success, or non-zero on failure
  */
  int (*base64_encode)(const unsigned char *in, size_t in_len,
                      unsigned char *out, size_t *out_len);

} oci_signer_params_t;

/** @brief get signing string
 *
 * @param[in] signer_params      Pointer to a struct of signer parameters
 * @param[out] signing_string    Struct of buffer to store signing string
 * @param[in] signing_string_max_len Maximum length of the signing_string buffer
 * @param[out] signed_headers    Struct of buffer to store signed headers string
 * @param[in] signed_headers_max_len Maximum length of the signed_headers buffer
 * @return OCI_SIGNER_OK on success, or one of the error codes:
 *         OCI_SIGNER_INVALID_INPUT_ERROR if any input parameter is invalid
 *         OCI_SIGNER_INVALID_HEADER_ERROR if a header handler returns NULL
 *         OCI_SIGNER_SIGNING_STRING_OVERFLOW_ERROR if signing_string buffer would overflow
 *         OCI_SIGNER_SIGNING_HEADERS_OVERFLOW_ERROR if signed_headers buffer would overflow
 */
int get_signing_string(oci_signer_params_t *signer_params,
                      oci_signer_str_t *signing_string,
                      size_t signing_string_max_len,
                      oci_signer_str_t *signed_headers,
                      size_t signed_headers_max_len);

/** @brief perform OCI signing
 *
 * @param[in] signer_params  A pointer to a struct of signer parameters
 *                           Note: private_key must be in DER format
 * @param[out] auth_header   A struct to store Authorization header name and value. The recommended minimum memory allocated for the buffer is 3072 bytes.
 *                           The function will set auth_header->key to "authorization".
 *                           auth_header->value.data must point to a buffer allocated by the caller. The function will write the Authorization header value to this buffer.
 *                           auth_header->value.len will be set to the length of the generated header value.
 * @param[in] auth_header_value_max_len Maximum length of the auth_header->value.data buffer.
 * @return Status code where zero for success and non-zero for failure:
 *         OCI_SIGNER_OK on success
 *         OCI_SIGNER_INVALID_INPUT_ERROR if any input parameter is invalid
 *         OCI_SIGNER_BUFFER_OVERFLOW_ERROR if auth_header buffer would overflow
 *         OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR if signing_string buffer would overflow
 *         OCI_SIGNER_SIGNING_HEADERS_BUFFER_OVERFLOW_ERROR if signed_headers buffer would overflow
 */
int oci_signer_sign(oci_signer_params_t *signer_params, oci_signer_header_t *auth_header, size_t auth_header_value_max_len);

#endif /* __OCI_SIGNER_H */