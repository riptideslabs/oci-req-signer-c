#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>
#include <openssl/err.h>

#include "oci_signer.h"

// Example-specific buffer size constants
#define EXAMPLE_AUTH_HEADER_MAX_LEN 4096

// Test private key in PEM format (from http_signer_test.go)
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
    if (!buf)
    {
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

    if (EVP_PKEY_sign(ctx, sig, sig_len, sha256_digest_data, sha256_digest_len) <= 0)
    {
        EVP_PKEY_CTX_free(ctx);
        EVP_PKEY_free(pkey);
        return -1;
    }

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    return 0;
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

int main()
{
    // Convert PEM to DER format
    unsigned char *key_data = NULL;
    size_t key_len = 0;

    if (convert_pem_to_der(test_private_key_pem, &key_data, &key_len) != 0) 
    {
        fprintf(stderr, "Failed to convert PEM to DER format\n");
        return 1;
    }

    printf("Successfully converted PEM to DER format (%zu bytes)\n", key_len);

    // Sample request parameters
    const char *method = "GET";
    const char *uri = "/20160918/instances";
    const char *host = "iaas.us-phoenix-1.oraclecloud.com";
    const char *date = "Thu, 05 Jan 2014 21:31:40 GMT";
    const char *payload = "";
    // Example key_id in format: tenancy/user/fingerprint
    const char *key_id =
        "ocid1.tenancy.oc1..aaaaaaaaba3pv6wkcr4jqae5f15p2b2m2yt2j6rx32uzr4h25vqstifsfdsq/"
        "ocid1.user.oc1..aaaaaaaat5nvwcna5j6aqzjcaty5eqbb6qt2jvpkanghtgdaqedqw3rynjq/"
        "20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34";

    // Alternative: Example key_id using session token format
    // const char *key_id = "ST$aaaaaaaa7tz3aaaaaaaaaymq2maaaaaaabfwiljtdnfgqaaaa";

    // Initialize OCI signer parameters
    oci_signer_params_t signer_params = {0}; // Zero-initialize the structure

    // Set the private key in DER format using the binary type
    signer_params.private_key.data = key_data;
    signer_params.private_key.len = key_len;
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
    unsigned char *auth_header_buf = malloc(EXAMPLE_AUTH_HEADER_MAX_LEN);
    memset(auth_header_buf, 0, EXAMPLE_AUTH_HEADER_MAX_LEN);
    oci_signer_header_t auth_header = 
    {
        .value = {.data = auth_header_buf}
    };

    int status = oci_signer_sign(&signer_params, &auth_header, EXAMPLE_AUTH_HEADER_MAX_LEN);

    if (status == OCI_SIGNER_OK) 
    {
        printf("Authorization header value: %.*s\n", auth_header.value.len, auth_header.value.data);
    }
    else 
    {
        fprintf(stderr, "Failed to sign the request\n");
    }

    free(auth_header_buf);
    free(key_data);
    return (status == OCI_SIGNER_OK) ? 0 : 1;
}