/*
 * Copyright (c) 2025 Riptides Labs, Inc.
 * SPDX-License-Identifier: MIT
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <ctype.h>
#include <check.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

#include "oci_signer.h"

// Test-specific buffer size constants
#define TEST_SIGNING_STRING_MAX_LEN 4096
#define TEST_AUTH_HEADER_MAX_LEN 4096

static const char *test_private_key_pem =
"-----BEGIN RSA PRIVATE KEY-----\n"
"MIICXgIBAAKBgQDCFENGw33yGihy92pDjZQhl0C36rPJj+CvfSC8+q28hxA161QF\n"
"NUd13wuCTUcq0Qd2qsBe/2hFyc2DCJJg0h1L78+6Z4UMR7EOcpfdUE9Hf3m/hs+F\n"
"UR45uBJeDK1HSFHD8bHKD6kv8FPGfJTotc+2xjJwoYi+1hqp1fIekaxsyQIDAQAB\n"
"AoGBAJR8ZkCUvx5kzv+utdl7T5MnordT1TvoXXJGXK7ZZ+UuvMNUCdN2QPc4sBiA\n"
"QWvLw1cSKt5DsKZ8UETpYPy8pPYnnDEz2dDYiaew9+xEpubyeW2oH4Zx71wqBtOK\n"
"kqwrXa/pzdpiucRRjk6vE6YY7EBBs/g7uanVpGibOVAEsqH1AkEA7DkjVH28WDUg\n"
"f1nqvfn2Kj6CT7nIcE3jGJsZZ7zlZmBmHFDONMLUrXR/Zm3pR5m0tCmBqa5RK95u\n"
"412jt1dPIwJBANJT3v8pnkth48bQo/fKel6uEYyboRtA5/uHuHkZ6FQF7OUkGogc\n"
"mSJluOdc5t6hI1VsLn0QZEjQZMEOWr+wKSMCQQCC4kXJEsHAve77oP6HtG/IiEn7\n"
"kpyUXRNvFsDE0czpJJBvL/aRFUJxuRK91jhjC68sA7NsKMGg5OXb5I5Jj36xAkEA\n"
"gIT7aFOYBFwGgQAQkWNKLvySgKbAZRTeLBacpHMuQdl1DfdntvAyqpAZ0lY0RKmW\n"
"G6aFKaqQfOXKCyWoUiVknQJAXrlgySFci/2ueKlIE1QqIiLSZ8V8OlpFLRnb1pzI\n"
"7U1yQXnTAEFYM560yJlzUpOb1V4cScGd365tiSMvxLOvTA==\n"
"-----END RSA PRIVATE KEY-----";

static const char *expected_signature_get = "GBas7grhyrhSKHP6AVIj/h5/Vp8bd/peM79H9Wv8kjoaCivujVXlpbKLjMPeDUhxkFIWtTtLBj3sUzaFj34XE6YZAHc9r2DmE4pMwOAy/kiITcZxa1oHPOeRheC0jP2dqbTll8fmTZVwKZOKHYPtrLJIJQHJjNvxFWeHQjMaR7M=";
static const char *expected_signature_post = "Mje8vIDPlwIHmD/cTDwRxE7HaAvBg16JnVcsuqaNRim23fFPgQfLoOOxae6WqKb1uPjYEl0qIdazWaBy/Ml8DRhqlocMwoSXv0fbukP8J5N80LCmzT/FFBvIvTB91XuXI3hYfP9Zt1l7S6ieVadHUfqBedWH0itrtPJBgKmrWso=";

// Function to convert PEM to DER format
static int convert_pem_to_der(const char *pem_data, unsigned char **der_data, size_t *der_len)
{
    BIO *bio_pem = NULL;
    EVP_PKEY *pkey = NULL;
    unsigned char *buf = NULL;
    int ret = -1;

    // Create a memory BIO for the PEM data
    bio_pem = BIO_new_mem_buf(pem_data, -1);
    if (!bio_pem)
    {
        fprintf(stderr, "Failed to create BIO for PEM data\n");
        goto cleanup;
    }

    // Read the private key from the PEM data
    pkey = PEM_read_bio_PrivateKey(bio_pem, NULL, NULL, NULL);
    if (!pkey)
    {
        fprintf(stderr, "Failed to read private key from PEM data\n");
        ERR_print_errors_fp(stderr);
        goto cleanup;
    }

    // Get the size of the DER encoding
    *der_len = i2d_PrivateKey(pkey, NULL);
    if (*der_len <= 0)
    {
        fprintf(stderr, "Failed to get DER encoding size\n");
        goto cleanup;
    }

    // Allocate memory for the DER encoding
    buf = malloc(*der_len);
    if (!buf) {
        fprintf(stderr, "Failed to allocate memory for DER data\n");
        goto cleanup;
    }

    // Convert to DER format
    unsigned char *p = buf;
    if (i2d_PrivateKey(pkey, &p) <= 0)
    {
        fprintf(stderr, "Failed to convert to DER format\n");
        goto cleanup;
    }

    *der_data = buf;
    buf = NULL;  // Transfer ownership to caller
    ret = 0;

cleanup:
    if (buf) free(buf);
    if (pkey) EVP_PKEY_free(pkey);
    if (bio_pem) BIO_free(bio_pem);

    return ret;
}

// Base64 encode function using OpenSSL
static int base64_encode(const unsigned char *in, size_t in_len,
                                unsigned char *out, size_t *out_len)
{
    
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, in, in_len);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    if (bufferPtr->length > *out_len) {
        BIO_free_all(bio);
        return -1;
    }

    memcpy(out, bufferPtr->data, bufferPtr->length);
    out[bufferPtr->length] = '\0';
    *out_len = bufferPtr->length;

    BIO_free_all(bio);
    return 0;
}

// RSA Sign function using OpenSSL
static int rsa_sign_sha256(const unsigned char *sha256_digest_data, size_t sha256_digest_len,
                         const unsigned char *pkcs1_key_data, size_t pkcs1_key_len,
                         unsigned char *sig, size_t *sig_len) {
    BIO *bio = BIO_new_mem_buf(pkcs1_key_data, pkcs1_key_len);
    if (!bio) return -1;

    EVP_PKEY *pkey = d2i_PrivateKey_bio(bio, NULL);
    BIO_free(bio);
    if (!pkey) return -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(pkey, NULL);
    if (!ctx)
    {
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_PKEY_sign_init(ctx) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Set padding to PKCS#1 v1.5
    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    // Set the hash type
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    if (EVP_PKEY_sign(ctx, sig, sig_len, sha256_digest_data, sha256_digest_len) <= 0) {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
}


// Helper function to check if a string contains a substring
static void ck_assert_str_contains(const char *str, const char *substr)
{
    ck_assert_msg(strstr(str, substr) != NULL, 
                 "Expected '%s' to contain '%s'", str, substr);
}

// Function to verify the signature part of the Authorization header
static void verify_signature(const unsigned char *auth_header_data, const char *expected_signature)
{
    // Find the signature part in the Authorization header
    const char *signature_start = strstr((char *)auth_header_data, "signature=\"");
    ck_assert_ptr_nonnull(signature_start);
    
    // Move past "signature=\""
    signature_start += 11;
    
    // Find the end of the signature
    const char *signature_end = strchr(signature_start, '"');
    ck_assert_ptr_nonnull(signature_end);
    
    // Calculate the length of the signature
    size_t signature_len = signature_end - signature_start;
    
    char actual_signature[256];
    memcpy(actual_signature, signature_start, signature_len);
    actual_signature[signature_len] = '\0'; // Null-terminate

    ck_assert_str_eq(actual_signature, expected_signature);
}

// --- Check setup/teardown for key_data and auth_header_buf ---
static unsigned char *global_key_data = NULL;
static size_t global_key_len = 0;
static unsigned char *global_auth_header_buf = NULL;

static void oci_signer_setup(void) {
    int ret = convert_pem_to_der(test_private_key_pem, &global_key_data, &global_key_len);
    ck_assert_int_eq(ret, 0);
    ck_assert_ptr_nonnull(global_key_data);
    ck_assert_uint_gt(global_key_len, 0);
    global_auth_header_buf = malloc(TEST_AUTH_HEADER_MAX_LEN);
    ck_assert_ptr_nonnull(global_auth_header_buf);
    memset(global_auth_header_buf, 0, TEST_AUTH_HEADER_MAX_LEN);
}

static void oci_signer_teardown(void) {
    if (global_key_data) {
        free(global_key_data);
        global_key_data = NULL;
        global_key_len = 0;
    }
    if (global_auth_header_buf) {
        free(global_auth_header_buf);
        global_auth_header_buf = NULL;
    }
}

// Test case for the OCI signer
START_TEST(OciSignerTest_Sign)
{
    // Sample request parameters - exactly matching the Go test
    const char *method = "GET";
    const char *uri = "/20160918/instances?availabilityDomain=Pjwf%3A%20PHX-AD-1&compartmentId=ocid1.compartment.oc1..aaaaaaaam3we6vgnherjq5q2idnccdflvjsnog7mlr6rtdb25gilchfeyjxa&displayName=TeamXInstances&volumeId=ocid1.volume.oc1.phx.abyhqljrgvttnlx73nmrwfaux7kcvzfs3s66izvxf2h4lgvyndsdsnoiwr5q";
    const char *host = "iaas.us-phoenix-1.oraclecloud.com";
    const char *date = "Thu, 05 Jan 2014 21:31:40 GMT";
    const char *payload = "";
    const char *key_id = 
        "ocid1.tenancy.oc1..aaaaaaaaba3pv6wkcr4jqae5f15p2b2m2yt2j6rx32uzr4h25vqstifsfdsq/"
        "ocid1.user.oc1..aaaaaaaat5nvwcna5j6aqzjcaty5eqbb6qt2jvpkanghtgdaqedqw3rynjq/"
        "20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34";

    // Initialize OCI signer parameters
    oci_signer_params_t signer_params = {0}; // Zero-initialize the structure
    
    // Set private key in DER format using the binary type
    signer_params.private_key.data = global_key_data;
    signer_params.private_key.len = global_key_len;
    
    signer_params.key_id = oci_signer_string((unsigned char *)key_id);
    signer_params.method = oci_signer_string((unsigned char *)method);
    signer_params.uri = oci_signer_string((unsigned char *)uri);
    signer_params.payload = oci_signer_string((unsigned char *)payload);
    signer_params.headers[0].key = oci_signer_string((unsigned char *)"host");
    signer_params.headers[0].value = oci_signer_string((unsigned char *)host);
    signer_params.headers[1].key = oci_signer_string((unsigned char *)"date");
    signer_params.headers[1].value = oci_signer_string((unsigned char *)date);
    signer_params.num_headers = 2;
    
    // Set the required crypto functions
    signer_params.sha256 = SHA256;
    signer_params.rsa_sign_sha256 = rsa_sign_sha256;
    signer_params.base64_encode = base64_encode;

    // Buffer for the Authorization header
    oci_signer_header_t auth_header = {
        .value = {.data = global_auth_header_buf}
    };

    // Sign the request
    int status = oci_signer_sign(&signer_params, &auth_header, TEST_AUTH_HEADER_MAX_LEN);
    
    // Check that signing was successful
    ck_assert_int_eq(status, OCI_SIGNER_OK);
    
    // Check that the Authorization header was set correctly
    ck_assert_ptr_nonnull(auth_header.value.data);
    ck_assert_uint_gt(auth_header.value.len, 0);

    ck_assert_str_eq((char *)auth_header.key.data, "Authorization");

    // Check that the Authorization header contains the expected components
    ck_assert_str_contains((char *)auth_header.value.data, "Signature");
    ck_assert_str_contains((char *)auth_header.value.data, "version=\"1\"");
    ck_assert_str_contains((char *)auth_header.value.data, "headers=\"date (request-target) host\"");
    ck_assert_str_contains((char *)auth_header.value.data, "algorithm=\"rsa-sha256\"");

    // Verify that the keyId in the authorization header contains the key ID
    char expected_key_id[512];
    snprintf(expected_key_id, sizeof(expected_key_id), "keyId=\"%s\"", key_id);
    ck_assert_str_contains((char *)auth_header.value.data, expected_key_id);
    
    // Verify the signature part with expected signature 
    verify_signature(auth_header.value.data, expected_signature_get);
}
END_TEST

// Test case for the OCI signer with POST request (body)
START_TEST(OciSignerTest_SignWithBody)
{
    // Sample request parameters for POST request
    const char *method = "POST";
    const char *uri = "/20160918/volumeAttachments";
    const char *host = "iaas.us-phoenix-1.oraclecloud.com";
    const char *date = "Thu, 05 Jan 2014 21:31:40 GMT";
    const char *payload =
"{\n"
"    \"compartmentId\": \"ocid1.compartment.oc1..aaaaaaaam3we6vgnherjq5q2idnccdflvjsnog7mlr6rtdb25gilchfeyjxa\",\n"
"    \"instanceId\": \"ocid1.instance.oc1.phx.abuw4ljrlsfiqw6vzzxb43vyypt4pkodawglp3wqxjqofakrwvou52gb6s5a\",\n"
"    \"volumeId\": \"ocid1.volume.oc1.phx.abyhqljrgvttnlx73nmrwfaux7kcvzfs3s66izvxf2h4lgvyndsdsnoiwr5q\"\n"
"}";
    const char *key_id = 
        "ocid1.tenancy.oc1..aaaaaaaaba3pv6wkcr4jqae5f15p2b2m2yt2j6rx32uzr4h25vqstifsfdsq/"
        "ocid1.user.oc1..aaaaaaaat5nvwcna5j6aqzjcaty5eqbb6qt2jvpkanghtgdaqedqw3rynjq/"
        "20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34";
    
    // Initialize OCI signer parameters
    oci_signer_params_t signer_params = {0}; // Zero-initialize the structure
    // Set private key in DER format using the binary type
    signer_params.private_key.data = global_key_data;
    signer_params.private_key.len = global_key_len;
    
    signer_params.key_id = oci_signer_string((unsigned char *)key_id);
    signer_params.method = oci_signer_string((unsigned char *)method);
    signer_params.uri = oci_signer_string((unsigned char *)uri);
    signer_params.payload = oci_signer_string((unsigned char *)payload);
    signer_params.headers[0].key = oci_signer_string((unsigned char *)"host");
    signer_params.headers[0].value = oci_signer_string((unsigned char *)host);
    signer_params.headers[1].key = oci_signer_string((unsigned char *)"date");
    signer_params.headers[1].value = oci_signer_string((unsigned char *)date);
    // Add content-type and content-length headers
    
    // Content-Type header
    signer_params.headers[2].key = oci_signer_string((unsigned char *)"content-type");
    signer_params.headers[2].value = oci_signer_string((unsigned char *)"application/json");

     // Content-Length header
    signer_params.headers[3].key = oci_signer_string((unsigned char *)"content-length");
    char content_length_str[32] = {0};
    snprintf(content_length_str, sizeof(content_length_str), "%zu", strlen(payload));
    signer_params.headers[3].value = oci_signer_string((unsigned char *)content_length_str);
    signer_params.num_headers = 4;
        
    // Set the required crypto functions
    signer_params.sha256 = SHA256;
    signer_params.rsa_sign_sha256 = rsa_sign_sha256;
    signer_params.base64_encode = base64_encode;
    
    // Buffer for the Authorization header
    oci_signer_header_t auth_header = {
        .value = {.data = global_auth_header_buf}
    };
    
    // Sign the request
    int status = oci_signer_sign(&signer_params, &auth_header, TEST_AUTH_HEADER_MAX_LEN);
    
    // Check that signing was successful
    ck_assert_int_eq(status, OCI_SIGNER_OK);
    
    // Check that the Authorization header was set correctly
    ck_assert_ptr_nonnull(auth_header.value.data);
    ck_assert_uint_gt(auth_header.value.len, 0);

    ck_assert_str_eq((char *)auth_header.key.data, "Authorization");
    
    // Check that the Authorization header contains the expected components
    ck_assert_str_contains((char *)auth_header.value.data, "Signature");
    ck_assert_str_contains((char *)auth_header.value.data, "version=\"1\"");
    ck_assert_str_contains((char *)auth_header.value.data, "headers=\"date (request-target) host content-length content-type x-content-sha256\"");
    ck_assert_str_contains((char *)auth_header.value.data, "algorithm=\"rsa-sha256\"");
    
    // Verify that the keyId in the Authorization header contains the key ID
    char expected_key_id[512];
    snprintf(expected_key_id, sizeof(expected_key_id), "keyId=\"%s\"", key_id);
    ck_assert_str_contains((char *)auth_header.value.data, expected_key_id);
    
    // Verify the signature part with expected signature
    verify_signature(auth_header.value.data, expected_signature_post);
    

}
END_TEST

// Test case for the OCI signer with session token
START_TEST(OciSignerTest_SessionToken)
{
    // Sample request parameters
    const char *method = "GET";
    const char *uri = "/20160918/instances?availabilityDomain=Pjwf%3A%20PHX-AD-1&compartmentId=ocid1.compartment.oc1..aaaaaaaam3we6vgnherjq5q2idnccdflvjsnog7mlr6rtdb25gilchfeyjxa&displayName=TeamXInstances&volumeId=ocid1.volume.oc1.phx.abyhqljrgvttnlx73nmrwfaux7kcvzfs3s66izvxf2h4lgvyndsdsnoiwr5q";
    const char *host = "iaas.us-phoenix-1.oraclecloud.com";
    const char *date = "Thu, 05 Jan 2014 21:31:40 GMT";
    const char *payload = "";
    // Use a session token key ID
    const char *session_token = "ST$aaaaaaaa7tz3aaaaaaaaaymq2maaaaaaabfwiljtdnfgqaaaa";
    
    // Initialize OCI signer parameters
    oci_signer_params_t signer_params = {0}; // Zero-initialize the structure
    // Set private key in DER format using the binary type
    signer_params.private_key.data = global_key_data;
    signer_params.private_key.len = global_key_len;
    
    signer_params.key_id = oci_signer_string((unsigned char *)session_token);
    signer_params.method = oci_signer_string((unsigned char *)method);
    signer_params.uri = oci_signer_string((unsigned char *)uri);
    signer_params.payload = oci_signer_string((unsigned char *)payload);
    signer_params.headers[0].key = oci_signer_string((unsigned char *)"host");
    signer_params.headers[0].value = oci_signer_string((unsigned char *)host);
    signer_params.headers[1].key = oci_signer_string((unsigned char *)"date");
    signer_params.headers[1].value = oci_signer_string((unsigned char *)date);
    signer_params.num_headers = 2;
    
    // Set the required crypto functions
    signer_params.sha256 = SHA256;
    signer_params.rsa_sign_sha256 = rsa_sign_sha256;
    signer_params.base64_encode = base64_encode;
    
    // Buffer for the Authorization header
    oci_signer_header_t auth_header = {
        .value = {.data = global_auth_header_buf}
    };
    
    // Sign the request
    int status = oci_signer_sign(&signer_params, &auth_header, TEST_AUTH_HEADER_MAX_LEN);
    
    // Check that signing was successful
    ck_assert_int_eq(status, OCI_SIGNER_OK);
    
    // Check that the Authorization header was set correctly
    ck_assert_ptr_nonnull(auth_header.value.data);
    ck_assert_uint_gt(auth_header.value.len, 0);

    ck_assert_str_eq((char *)auth_header.key.data, "Authorization");

    // Check that the Authorization header contains the expected components
    ck_assert_str_contains((char *)auth_header.value.data, "Signature");
    ck_assert_str_contains((char *)auth_header.value.data, "version=\"1\"");
    ck_assert_str_contains((char *)auth_header.value.data, "headers=\"");
    ck_assert_str_contains((char *)auth_header.value.data, "algorithm=\"rsa-sha256\"");
    
    // Verify that the keyId in the Authorization header contains the session token
    char expected_key_id[256];
    snprintf(expected_key_id, sizeof(expected_key_id), "keyId=\"%s\"", session_token);
    ck_assert_str_contains((char *)auth_header.value.data, expected_key_id);

    // Verify the signature part with expected signature 
    verify_signature(auth_header.value.data, expected_signature_get);
    

}
END_TEST

// Test case for the signing string generation
START_TEST(OciSignerTest_SigningString)
{
    // Sample request parameters
    const char *method = "GET";
    const char *uri = "/20160918/instances?availabilityDomain=Pjwf%3A%20PHX-AD-1&compartmentId=ocid1.compartment.oc1..aaaaaaaam3we6vgnherjq5q2idnccdflvjsnog7mlr6rtdb25gilchfeyjxa&displayName=TeamXInstances&volumeId=ocid1.volume.oc1.phx.abyhqljrgvttnlx73nmrwfaux7kcvzfs3s66izvxf2h4lgvyndsdsnoiwr5q";
    const char *host = "iaas.us-phoenix-1.oraclecloud.com";
    const char *date = "Thu, 05 Jan 2014 21:31:40 GMT";
    const char *payload = "";
    const char *key_id = 
        "ocid1.tenancy.oc1..aaaaaaaaba3pv6wkcr4jqae5f15p2b2m2yt2j6rx32uzr4h25vqstifsfdsq/"
        "ocid1.user.oc1..aaaaaaaat5nvwcna5j6aqzjcaty5eqbb6qt2jvpkanghtgdaqedqw3rynjq/"
        "20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34";
    
    // Initialize OCI signer parameters
    oci_signer_params_t signer_params = {0}; // Zero-initialize the structure
    // Set private key in DER format using the binary type
    signer_params.private_key.data = global_key_data;
    signer_params.private_key.len = global_key_len;
    
    signer_params.key_id = oci_signer_string((unsigned char *)key_id);
    signer_params.method = oci_signer_string((unsigned char *)method);
    signer_params.uri = oci_signer_string((unsigned char *)uri);
    signer_params.payload = oci_signer_string((unsigned char *)payload);
    signer_params.headers[0].key = oci_signer_string((unsigned char *)"host");
    signer_params.headers[0].value = oci_signer_string((unsigned char *)host);
    signer_params.headers[1].key = oci_signer_string((unsigned char *)"date");
    signer_params.headers[1].value = oci_signer_string((unsigned char *)date);
    signer_params.num_headers = 2;
    
    // Set the required crypto functions
    signer_params.sha256 = SHA256;
    signer_params.rsa_sign_sha256 = rsa_sign_sha256;
    signer_params.base64_encode = base64_encode;
    
    // Buffer for the signing string
    unsigned char signing_string_buf[TEST_SIGNING_STRING_MAX_LEN] = {0};
    oci_signer_str_t signing_string = {.data = signing_string_buf};

    // Buffer for the signing headers string
    unsigned char signing_headers_buf[TEST_AUTH_HEADER_MAX_LEN] = {0};
    oci_signer_str_t signing_headers = {.data = signing_headers_buf};

    // Get the signing string
    int status = get_signing_string(&signer_params, &signing_string, TEST_SIGNING_STRING_MAX_LEN, 
                                   &signing_headers, TEST_AUTH_HEADER_MAX_LEN);
    
    // Check that signing string generation was successful
    ck_assert_int_eq(status, OCI_SIGNER_OK);
    ck_assert_ptr_nonnull(signing_string.data);
    ck_assert_uint_gt(signing_string.len, 0);

    
    // Check that the signing string contains the expected components
    ck_assert_str_contains((char *)signing_string.data, "date: Thu, 05 Jan 2014 21:31:40 GMT");
    ck_assert_str_contains((char *)signing_string.data, "(request-target): get /20160918/instances");
    ck_assert_str_contains((char *)signing_string.data, "host: iaas.us-phoenix-1.oraclecloud.com");
    

}
END_TEST

// Test case for the signing string generation when there is a body
START_TEST(OciSignerTest_SigningStringWithBody)
{
    // Sample request parameters
    const char *method = "POST";
    const char *uri = "/20160918/volumeAttachments";
    const char *host = "iaas.us-phoenix-1.oraclecloud.com";
    const char *date = "Thu, 05 Jan 2014 21:31:40 GMT";
    const char *payload =
"{\n"
"    \"compartmentId\": \"ocid1.compartment.oc1..aaaaaaaam3we6vgnherjq5q2idnccdflvjsnog7mlr6rtdb25gilchfeyjxa\",\n"
"    \"instanceId\": \"ocid1.instance.oc1.phx.abuw4ljrlsfiqw6vzzxb43vyypt4pkodawglp3wqxjqofakrwvou52gb6s5a\",\n"
"    \"volumeId\": \"ocid1.volume.oc1.phx.abyhqljrgvttnlx73nmrwfaux7kcvzfs3s66izvxf2h4lgvyndsdsnoiwr5q\"\n"
"}";
    const char *key_id = 
        "ocid1.tenancy.oc1..aaaaaaaaba3pv6wkcr4jqae5f15p2b2m2yt2j6rx32uzr4h25vqstifsfdsq/"
        "ocid1.user.oc1..aaaaaaaat5nvwcna5j6aqzjcaty5eqbb6qt2jvpkanghtgdaqedqw3rynjq/"
        "20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34";
    
    // Initialize OCI signer parameters
    oci_signer_params_t signer_params = {0}; // Zero-initialize the structure
    // Set private key in DER format using the binary type
    signer_params.private_key.data = global_key_data;
    signer_params.private_key.len = global_key_len;
    
    signer_params.key_id = oci_signer_string((unsigned char *)key_id);
    signer_params.method = oci_signer_string((unsigned char *)method);
    signer_params.uri = oci_signer_string((unsigned char *)uri);
    signer_params.payload = oci_signer_string((unsigned char *)payload);
    signer_params.headers[0].key = oci_signer_string((unsigned char *)"host");
    signer_params.headers[0].value = oci_signer_string((unsigned char *)host);
    signer_params.headers[1].key = oci_signer_string((unsigned char *)"date");
    signer_params.headers[1].value = oci_signer_string((unsigned char *)date);
    signer_params.num_headers = 2;
    
    // Set the required crypto functions
    signer_params.sha256 = SHA256;
    signer_params.rsa_sign_sha256 = rsa_sign_sha256;
    signer_params.base64_encode = base64_encode;
    
    // Buffer for the signing string
    unsigned char signing_string_buf[TEST_SIGNING_STRING_MAX_LEN] = {0};
    oci_signer_str_t signing_string = {.data = signing_string_buf};

    // Buffer for the signing headers string
    unsigned char signing_headers_buf[TEST_AUTH_HEADER_MAX_LEN] = {0};
    oci_signer_str_t signing_headers = {.data = signing_headers_buf};
    
    // Get the signing string
    int status = get_signing_string(&signer_params, &signing_string, TEST_SIGNING_STRING_MAX_LEN, 
                                   &signing_headers, TEST_AUTH_HEADER_MAX_LEN);

    // Check that signing string generation was successful
    ck_assert_int_eq(status, OCI_SIGNER_OK);
    ck_assert_ptr_nonnull(signing_string.data);
    ck_assert_uint_gt(signing_string.len, 0);

    
    // Check that the signing string contains the expected components
    ck_assert_str_contains((char *)signing_string.data, "date: Thu, 05 Jan 2014 21:31:40 GMT");
    ck_assert_str_contains((char *)signing_string.data, "(request-target): post /20160918/volumeAttachments");
    ck_assert_str_contains((char *)signing_string.data, "host: iaas.us-phoenix-1.oraclecloud.com");
    ck_assert_str_contains((char *)signing_string.data, "content-length: 316");
    ck_assert_str_contains((char *)signing_string.data, "content-type: application/json");
    ck_assert_str_contains((char *)signing_string.data, "x-content-sha256: V9Z20UJTvkvpJ50flBzKE32+6m2zJjweHpDMX/U4Uy0=");
    

}
END_TEST

// Test suite
Suite *oci_signer_suite(void)
{
    Suite *s = suite_create("OCI Signer");
    
    TCase *tc_core = tcase_create("Core");
    tcase_add_checked_fixture(tc_core, oci_signer_setup, oci_signer_teardown);
    tcase_add_test(tc_core, OciSignerTest_Sign);
    tcase_add_test(tc_core, OciSignerTest_SignWithBody);
    tcase_add_test(tc_core, OciSignerTest_SessionToken);
    tcase_add_test(tc_core, OciSignerTest_SigningString);
    tcase_add_test(tc_core, OciSignerTest_SigningStringWithBody);
    suite_add_tcase(s, tc_core);
    
    return s;
}

int main(void)
{
    Suite *s = oci_signer_suite();
    SRunner *sr = srunner_create(s);
    
    srunner_run_all(sr, CK_NORMAL);
    int number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);
    
    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
