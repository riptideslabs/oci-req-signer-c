#include "oci_signer.h"

#define OCI_SIGNER_AUTH_HEADER_NAME "Authorization"
#define OCI_SIGNER_SIGNING_ALGORITHM "rsa-sha256"
#define OCI_SIGNER_VERSION "1"

/*
 * Headers used in the signing process:
 * - date
 * - (request-target)
 * - host
 * - x-date (if present, use instead of date)
 */
#define OCI_SIGNER_DEFAULT_GENERIC_HEADERS 4

/*
 * Additional headers used in the signing process when there is a body in the request:
 * - content-length
 * - content-type
 * - x-content-sha256
 */
#define OCI_SIGNER_DEFAULT_BODY_HEADERS 3

#define OCI_SIGNER_BASE64_SIGNING_STRING_SIGNATURE_SIZE 684 // max length for base64 encoding of the RSA signature (assuming 4096-bit or smaller RSA key)
#define OCI_SIGNER_SHA256_DIGEST_SIZE 32 // SHA256 digest size in bytes
#define OCI_SIGNER_BASE64_SHA256_SIZE 44  // Base64 encoding of SHA256 digest (32 bytes) is 44 bytes
#define OCI_SIGNER_SIGNING_HEADERS_LIST_SIZE 74 // max length for the list of signing headers

/*
 * Object Storage API
 */
static const char *oci_object_storage_api_endpoint_prefix = "objectstorage.";
static const char *oci_object_storage_api_path_prefix = "/n/";

/*
* Streaming API
*/
static const char *oci_streaming_api_endpoint_prefix = "streaming.";
static const char *oci_streaming_api_path_prefix = "/20180418/streams/";

/*
* Generic Artifacts API
*/
static const char *oci_generic_artifacts_api_endpoint_prefix = "generic.artifacts.";
static const char *oci_generic_artifacts_api_path_prefix = "/20160918/generic/repositories/";


// Function pointer type for header handlers
// Returns: error code (OCI_SIGNER_OK on success)
// Parameters:
//   signer_params: The signer parameters
//   signing_str: The buffer to write to
//   max_len: Maximum length of the buffer
//   end_ptr: Output parameter that will point to the end of the written string
//   signing_header_name: The name of the header being processed
typedef int (*header_handler_t)(oci_signer_params_t *signer_params, unsigned char *signing_str, 
                               size_t max_len, unsigned char **end_ptr, const char *signing_header_name);

// Define the header handler entry structure
typedef struct {
  const char *header_name;
  header_handler_t handler;
} header_handler_entry_t;


int oci_signer_empty_str(oci_signer_str_t *str)
{
  return (str == NULL || str->data == NULL || str->len == 0) ? 1 : 0;
}

int oci_signer_empty_binary(oci_signer_binary_t *bin)
{
  return (bin == NULL || bin->data == NULL || bin->len == 0) ? 1 : 0;
}

oci_signer_str_t oci_signer_string(const unsigned char *cstr)
{
  oci_signer_str_t ret = {.data = NULL};
  if (cstr)
  {
    ret.data = (unsigned char *)cstr;
    ret.len = strlen((char *)cstr);
  }
  return ret;
}

int oci_signer_strcmp(oci_signer_str_t *str1, oci_signer_str_t *str2)
{
  size_t len = str1->len <= str2->len ? str1->len : str2->len;
  return strncmp((char *)str1->data, (char *)str2->data, len);
}

/* reference: http://lxr.nginx.org/source/src/core/ngx_string.c */
static unsigned char *oci_signer_vslprintf(unsigned char *buf, unsigned char *last,
                                        const char *fmt, va_list args)
{
  unsigned char *c_ptr = buf;
  oci_signer_str_t *str;

  while (*fmt && c_ptr < last)
  {
    size_t n_max = last - c_ptr;
    if (*fmt == '%')
    {
      if (*(fmt + 1) == 'V')
      {
        str = va_arg(args, oci_signer_str_t *);
        if (oci_signer_empty_str(str))
        {
          goto finished;
        }
        size_t cp_len = n_max >= str->len ? str->len : n_max;
        strncpy((char *)c_ptr, (char *)str->data, cp_len);
        c_ptr += cp_len;
        fmt += 2;
      }
      else
      {
        *(c_ptr++) = *(fmt++);
      }
    }
    else
    {
      *(c_ptr++) = *(fmt++);
    }
  }
  *c_ptr = '\0';
finished:
  return c_ptr;
}

// static unsigned char *oci_signer_sprintf(unsigned char *buf, const char *fmt, ...)
// {
//   va_list args;
//   va_start(args, fmt);

//   unsigned char *dst = oci_signer_vslprintf(buf, (void *)-1, fmt, args);
//   va_end(args);
//   return dst;
// }

static unsigned char *oci_signer_snprintf(unsigned char *buf, unsigned int n, const char *fmt, ...)
{
  va_list args;
  va_start(args, fmt);
  unsigned char *dst = oci_signer_vslprintf(buf, buf + n, fmt, args);
  va_end(args);
  return dst;
}

/**
 * @brief Convert a string to lowercase
 * 
 * @param[in] str The string to convert
 * @param[out] str_lower Buffer to store the lowercase string
 * @param[in] max_len Maximum length of the buffer
 */
static void oci_signer_to_lowercase(const oci_signer_str_t *str, char *str_lower, size_t max_len)
{
  size_t i;
  for (i = 0; i < str->len && i < max_len - 1; i++)
  {
    str_lower[i] = tolower(str->data[i]);
  }
  str_lower[i] = '\0';
}

bool oci_signer_should_exclude_body_signing(oci_signer_str_t *method, oci_signer_str_t *host, oci_signer_str_t *uri)
{
  if (oci_signer_empty_str(method) || oci_signer_empty_str(host) || oci_signer_empty_str(uri))
  {
    return false;
  }

  // if it's a `PutObject` or `UploadPart` Object Storage API call, we don't hash the body
  if
  (
    strncasecmp((char *)method->data, "put", method->len) == 0 && 
    strncasecmp((char *)host->data, oci_object_storage_api_endpoint_prefix, strlen(oci_object_storage_api_endpoint_prefix)) == 0 &&
    strncasecmp((char *)uri->data, oci_object_storage_api_path_prefix, strlen(oci_object_storage_api_path_prefix)) == 0
  )
  {
    return true;
  }

  // if it's a `PutMessages` Streaming API call, we don't hash the body
  if
  (
    strncasecmp((char *)method->data, "post", method->len) == 0 && 
    strncasecmp((char *)host->data, oci_streaming_api_endpoint_prefix, strlen(oci_streaming_api_endpoint_prefix)) == 0 && 
    strncasecmp((char *)uri->data, oci_streaming_api_path_prefix, strlen(oci_streaming_api_path_prefix)) == 0
  )
  {
    return true;
  }

  // if it's a `PutGenericArtifactContentByPath` Generic Artifacts Content API call, we don't hash the body
  if
  (
    strncasecmp((char *)method->data, "put", method->len) == 0 &&  
    strncasecmp((char *)host->data, oci_generic_artifacts_api_endpoint_prefix, strlen(oci_generic_artifacts_api_endpoint_prefix)) == 0 && 
    strncasecmp((char *)uri->data, oci_generic_artifacts_api_path_prefix, strlen(oci_generic_artifacts_api_path_prefix)) == 0
  )
  {
    return true;
  }
  

  // If not any of the special cases from above than hash body for POST, PUT, and PATCH methods
  return !(strncasecmp((char *)method->data, "post", method->len) == 0 ||
          strncasecmp((char *)method->data, "put", method->len) == 0 ||
          strncasecmp((char *)method->data, "patch", method->len) == 0);
}


static int get_request_target(oci_signer_params_t *signer_params, oci_signer_str_t *request_target, size_t max_len)
{
  // Convert method to lowercase
  char method_lower[8] = {0};  // Enough for the longest standard HTTP method
  oci_signer_to_lowercase(&signer_params->method, method_lower, sizeof(method_lower));
  
  size_t method_len = strlen(method_lower);
  
  // Check if we have enough space for method + space + URI
  size_t total_required_len = method_len + 1 + signer_params->uri.len;
  if (total_required_len > max_len)
  {
    return OCI_SIGNER_REQUEST_TARGET_BUFFER_OVERFLOW_ERROR;
  }
  
  unsigned char *str = request_target->data;
  
  // Copy the method
  memcpy(str, method_lower, method_len);
  str += method_len;
  
  // Add a space
  *str++ = ' ';
  
  // Copy the URI
  memcpy(str, signer_params->uri.data, signer_params->uri.len);
  str += signer_params->uri.len;
  
  request_target->len = str - request_target->data;
  return OCI_SIGNER_OK;
}

// Handler for simple headers like "date", "content-type", "content-encoding", etc.
static int handle_simple_header(oci_signer_params_t *signer_params, unsigned char *signing_str, 
                               size_t max_len, unsigned char **end_ptr, const char *signing_header_name) 
{
  unsigned int i;
  for (i = 0; i < signer_params->num_headers; i++)
  {
    if (strncasecmp((char *)signer_params->headers[i].key.data, signing_header_name, signer_params->headers[i].key.len) == 0)
    {
      oci_signer_str_t h = oci_signer_string((unsigned char *)signing_header_name);
      
      // Calculate required space
      size_t required_space = h.len + 2 + signer_params->headers[i].value.len; // header + ": " + value
      
      // Check if we have enough space
      if (required_space >= max_len)
      {
        return OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR;
      }
      
      // Write to the buffer
      *end_ptr = oci_signer_snprintf(signing_str, max_len, "%V: %V", &h, &signer_params->headers[i].value);
      
      return OCI_SIGNER_OK;
    }
  }
  return OCI_SIGNER_INVALID_HEADER_ERROR;
}


// Handler for the "(request-target)" header
static int handle_request_target(oci_signer_params_t *signer_params, unsigned char *signing_str, 
                                size_t max_len, unsigned char **end_ptr, const char *header_name)
{
  (void)header_name; // Unused parameter

  // A reasonable maximum for size needed for request_target_buf:
  // which is formed as HTTP method (max 8 bytes) + space (1 byte) + URI (variable)
  // is 2048 bytes
  unsigned char request_target_buf[2048] = {0};
  oci_signer_str_t request_target = {.data = request_target_buf};
  
  // Get the request target
  int rc = get_request_target(signer_params, &request_target, 2048);
  if (rc != OCI_SIGNER_OK)
  {
    return rc;
  }
  
  // Calculate the required space for the header
  // Format: "(request-target): %V" - need space for the prefix, colon, space, and request target
  size_t required_space = strlen("(request-target): ") + request_target.len;
  
  // Check if we have enough space in the buffer
  if (required_space >= max_len)
  {
    return OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR;
  }
  
  // Now it's safe to write to the actual buffer
  *end_ptr = oci_signer_snprintf(signing_str, max_len, "(request-target): %V", &request_target);
  
  return OCI_SIGNER_OK;
}

static int u64_to_str(unsigned long long value, char *buf, size_t bufsize)
{
    // bufsize must be at least 2 for "0" and null terminator
    if (bufsize < 2) return -1;
    size_t i = bufsize - 1;
    buf[i] = '\0';
    if (value == 0)
    {
        buf[--i] = '0';
    } else {
        while (value > 0 && i > 0)
        {
            buf[--i] = '0' + (value % 10);
            value /= 10;
        }
    }
    // Shift result to beginning of buffer
    size_t len = bufsize - 1 - i;
    memmove(buf, buf + i, len + 1); // include null terminator
    return len;
}

// Handler for the "content-length" header
static int handle_content_length(oci_signer_params_t *signer_params, unsigned char *signing_str, 
                                size_t max_len, unsigned char **end_ptr, const char *signing_header_name)
{
  // Find content-length in headers
  unsigned int i;
  for (i = 0; i < signer_params->num_headers; i++)
  {
    if (strncasecmp((char *)signer_params->headers[i].key.data, signing_header_name, signer_params->headers[i].key.len) == 0)
    {
      // Calculate required space
      size_t required_space = strlen("content-length: ") + signer_params->headers[i].value.len;
      
      // Check if we have enough space
      if (required_space >= max_len)
      {
        return OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR;
      }
      
      // Write to the buffer
      *end_ptr = oci_signer_snprintf(signing_str, max_len, "content-length: %V", &signer_params->headers[i].value);
      
      return OCI_SIGNER_OK;
    }
  }
  
  // If not found, use the payload length
  char content_length_str[32];
  u64_to_str(signer_params->payload.len, content_length_str, sizeof(content_length_str));
  oci_signer_str_t content_length = oci_signer_string((unsigned char *)content_length_str);

  // Calculate required space
  size_t required_space = strlen("content-length: ") + content_length.len;
  
  // Check if we have enough space
  if (required_space >= max_len)
  {
    return OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR;
  }
  
  // Write to the buffer
  *end_ptr = oci_signer_snprintf(signing_str, max_len, "content-length: %V", &content_length);
  
  return OCI_SIGNER_OK;
}

// Handler for the "content-type" header
static int handle_content_type(oci_signer_params_t *signer_params, unsigned char *signing_str, 
                              size_t max_len, unsigned char **end_ptr, const char *signing_header_name)
{
  // Find content-type in headers
  unsigned int i;
  for (i = 0; i < signer_params->num_headers; i++)
  {
    if (strncasecmp((char *)signer_params->headers[i].key.data, signing_header_name, signer_params->headers[i].key.len) == 0)
    {
      // Calculate required space
      size_t required_space = strlen("content-type: ") + signer_params->headers[i].value.len;
      
      // Check if we have enough space
      if (required_space >= max_len)
      {
        return OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR;
      }
      
      // Write to the buffer
      *end_ptr = oci_signer_snprintf(signing_str, max_len, "content-type: %V", &signer_params->headers[i].value);
      
      return OCI_SIGNER_OK;
    }
  }
  
  // If not found, use a default
  // Calculate required space for default content-type
  size_t required_space = strlen("content-type: application/json");
  
  // Check if we have enough space
  if (required_space >= max_len)
  {
    return OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR;
  }
  
  // Write to the buffer
  *end_ptr = oci_signer_snprintf(signing_str, max_len, "content-type: application/json");
  
  return OCI_SIGNER_OK;
}

// Handler for the "x-content-sha256" header
static int handle_x_content_sha256(oci_signer_params_t *signer_params, unsigned char *signing_str, 
                                  size_t max_len, unsigned char **end_ptr, const char *signing_header_name)
{
  // Find x-content-sha256 in headers
  unsigned int i;
  for (i = 0; i < signer_params->num_headers; i++)
  {
    if (strncasecmp((char *)signer_params->headers[i].key.data, signing_header_name, signer_params->headers[i].key.len) == 0)
    {
      // Calculate required space
      size_t required_space = strlen("x-content-sha256: ") + signer_params->headers[i].value.len;
      
      // Check if we have enough space
      if (required_space >= max_len)
      {
        return OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR;
      }
      
      // Write to the buffer
      *end_ptr = oci_signer_snprintf(signing_str, max_len, "x-content-sha256: %V", &signer_params->headers[i].value);
      
      return OCI_SIGNER_OK;
    }
  }

  // If not found, calculate the SHA256 hash
  unsigned char sha256_buf[OCI_SIGNER_SHA256_DIGEST_SIZE];
  signer_params->sha256(signer_params->payload.data, signer_params->payload.len, sha256_buf);
  
  // Base64 encode the hash
  unsigned char base64_buf[OCI_SIGNER_BASE64_SHA256_SIZE + 1] = {0}; // +1 for null terminator
  size_t out_len = OCI_SIGNER_BASE64_SHA256_SIZE + 1;

  int rc = 0;
  rc = signer_params->base64_encode(sha256_buf, OCI_SIGNER_SHA256_DIGEST_SIZE, base64_buf, &out_len);
  if (rc != 0)
  {
    return OCI_BASE64_ENCODE_ERROR_BASE + rc;
  }
  base64_buf[out_len] = '\0';

  oci_signer_str_t base64_x_content = oci_signer_string((unsigned char *)base64_buf);

  // Calculate required space
  size_t required_space = strlen("x-content-sha256: ") + base64_x_content.len;
  
  // Check if we have enough space
  if (required_space >= max_len)
  {
    return OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR;
  }
  
  // Write to the buffer
  *end_ptr = oci_signer_snprintf(signing_str, max_len, "x-content-sha256: %V", &base64_x_content);
  
  return OCI_SIGNER_OK;
}


// Default generic headers used in all requests
static const header_handler_entry_t generic_headers_handler[OCI_SIGNER_DEFAULT_GENERIC_HEADERS] =
{
  {"date", handle_simple_header},
  {"(request-target)", handle_request_target},
  {"host", handle_simple_header},
  {"x-date", handle_simple_header}
};

// Default body headers used for requests with a body (POST, PUT, PATCH)
static const header_handler_entry_t body_headers_handler[OCI_SIGNER_DEFAULT_BODY_HEADERS] =
{
  {"content-length", handle_content_length},
  {"content-type", handle_content_type},
  {"x-content-sha256", handle_x_content_sha256}
};

int get_signing_string(oci_signer_params_t *signer_params, oci_signer_str_t *signing_string, 
                     size_t signing_string_max_len, oci_signer_str_t *signing_headers_out, 
                     size_t signed_headers_max_len)
{
  if (signer_params == NULL || signing_string == NULL || signing_string->data == NULL || 
      signing_headers_out == NULL || signing_headers_out->data == NULL) 
  {
    return OCI_SIGNER_INVALID_INPUT_ERROR;
  }

  // Validate buffer sizes
  if (signing_string_max_len == 0 || signed_headers_max_len == 0)
  {
    return OCI_SIGNER_INVALID_INPUT_ERROR;
  }

   unsigned int i;
  // Get host from headers
  oci_signer_str_t *host = NULL;
  for (i = 0; i < signer_params->num_headers; i++)
  {
    if (strncasecmp((char *)signer_params->headers[i].key.data, "host", 4) == 0)
    {
      // Found host header
      host = &signer_params->headers[i].value;
      break;
    }
  }
  if (oci_signer_empty_str(host))
  {
    return OCI_SIGNER_INVALID_INPUT_ERROR;
  }


  unsigned char *str = signing_string->data;
  unsigned char *str_end = signing_string->data + signing_string_max_len - 1; // Reserve space for null terminator
  unsigned char *sh_str = signing_headers_out->data;
  unsigned char *sh_str_end = signing_headers_out->data + signed_headers_max_len - 1; // Reserve space for null terminator

  // headers to include in signature
  const header_handler_entry_t *signing_headers_handler[OCI_SIGNER_DEFAULT_GENERIC_HEADERS + OCI_SIGNER_DEFAULT_BODY_HEADERS] = {0};
  unsigned int num_signing_headers = 0;

  bool x_date_present = false;
  for (i = 0; i < signer_params->num_headers; i++)
  {
    if (strncasecmp((char *)signer_params->headers[i].key.data, "x-date", 6) == 0)
    {
      x_date_present = true;
      break;
    }
  }
  
  // Add default generic headers
  for (i = 0; i < OCI_SIGNER_DEFAULT_GENERIC_HEADERS && num_signing_headers < OCI_SIGNER_DEFAULT_GENERIC_HEADERS + OCI_SIGNER_DEFAULT_BODY_HEADERS; i++) 
  {
    // Skip "date" header if "x-date" is present
    if (x_date_present && strncasecmp(generic_headers_handler[i].header_name, "date", 4) == 0)
    {
      continue;
    }

    if (!x_date_present && strncasecmp(generic_headers_handler[i].header_name, "x-date", 6) == 0)
    {
      continue;
    }

    signing_headers_handler[num_signing_headers++] = &generic_headers_handler[i];
  }
  
  // Add default body headers if we should include the sha256 hash of body into the signing string
  if (!oci_signer_should_exclude_body_signing(&signer_params->method, host, &signer_params->uri))
  {
    for (i = 0; i < OCI_SIGNER_DEFAULT_BODY_HEADERS && num_signing_headers < OCI_SIGNER_DEFAULT_GENERIC_HEADERS + OCI_SIGNER_DEFAULT_BODY_HEADERS; i++)
    {
      signing_headers_handler[num_signing_headers++] = &body_headers_handler[i];
    }
  }

  // Process each header and add it to the signing string
  for (i = 0; i < num_signing_headers; i++)
  {
    // Check if we have enough space for a newline
    if (i > 0)
    {
      if (str + 1 >= str_end)
      {
        return OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR;
      }
      str = oci_signer_snprintf(str, str_end - str, "\n");
    }

    // Check if we have enough space for the header
    size_t remaining_space = str_end - str;
    if (remaining_space <= 0)
    {
      return OCI_SIGNER_SIGNING_STRING_BUFFER_OVERFLOW_ERROR;
    }

    // Call the header handler with bounds checking
    unsigned char *new_str = NULL;
    int rc = signing_headers_handler[i]->handler(signer_params, str, remaining_space, &new_str, signing_headers_handler[i]->header_name);
    if (rc != OCI_SIGNER_OK)
    {
      return rc;
    }

    str = new_str;

    // list of signing headers
    if (i > 0) 
    {
      // Check if we have enough space for a space
      if (sh_str + 1 >= sh_str_end)
      {
        return OCI_SIGNER_SIGNING_HEADERS_BUFFER_OVERFLOW_ERROR;
      }
      sh_str = oci_signer_snprintf(sh_str, sh_str_end - sh_str, " ");
    }

    // Check if we have enough space for the header name
    oci_signer_str_t header_name = 
    { 
      .data = (unsigned char *)signing_headers_handler[i]->header_name, 
      .len = strlen(signing_headers_handler[i]->header_name) 
    };
    
    size_t remaining_sh_space = sh_str_end - sh_str;
    if (remaining_sh_space <= header_name.len)
    {
      return OCI_SIGNER_SIGNING_HEADERS_BUFFER_OVERFLOW_ERROR;
    }
    
    unsigned char *new_sh_str = oci_signer_snprintf(sh_str, remaining_sh_space, "%V", &header_name);
    sh_str = new_sh_str;
  }
  
  // Set the length of the list of signing headers
  signing_headers_out->len = sh_str - signing_headers_out->data;

  // Remove the trailing newline if present
  if (str > signing_string->data && *(str - 1) == '\n')
  {
    str--;
  }
  signing_string->len = str - signing_string->data;

  return OCI_SIGNER_OK;
}

int oci_signer_sign(oci_signer_params_t *signer_params, oci_signer_header_t *auth_header, size_t auth_header_value_max_len)
{
  int rc = OCI_SIGNER_OK;

  // Validate input parameters
  if (auth_header == NULL || signer_params == NULL ||
      oci_signer_empty_binary(&signer_params->private_key) ||
      oci_signer_empty_str(&signer_params->key_id) ||
      oci_signer_empty_str(&signer_params->method) ||
      oci_signer_empty_str(&signer_params->uri) ||
      signer_params->sha256 == NULL ||
      signer_params->rsa_sign_sha256 == NULL ||
      signer_params->base64_encode == NULL ||
      signer_params->num_headers > OCI_SIGNER_MAX_NUM_HEADERS || signer_params->num_headers == 0 ||
      auth_header->value.data == NULL || auth_header_value_max_len <= 0)
  {
    return OCI_SIGNER_INVALID_INPUT_ERROR;
  }

  // Set the Authorization header name
  auth_header->key.data = (unsigned char *)OCI_SIGNER_AUTH_HEADER_NAME;
  auth_header->key.len = strlen(OCI_SIGNER_AUTH_HEADER_NAME);

  // Prepare buffers for the signing string and signed headers
  unsigned char *signing_string_buf = auth_header->value.data; // we can reuse the auth header value buffer for the signing string
  size_t signing_string_buf_size = auth_header_value_max_len;
  oci_signer_str_t signing_string = {.data = signing_string_buf, .len = 0};
  
  // longest list of signing headers is all headers concatenated with spaces: x-date (request-target) host x-content-sha256 content-length content-type
  // this fits into OCI_SIGNER_SIGNING_HEADERS_LIST_MAX_LEN
  unsigned char signing_headers_buf[OCI_SIGNER_SIGNING_HEADERS_LIST_SIZE] = {0};
  oci_signer_str_t signing_headers = {.data = signing_headers_buf, .len = 0};

  // Get the signing string and signed headers
  rc = get_signing_string(signer_params, &signing_string, signing_string_buf_size, 
                         &signing_headers, OCI_SIGNER_SIGNING_HEADERS_LIST_SIZE);
  if (rc != OCI_SIGNER_OK)
  {
    return rc;
  }

  // Calculate SHA256 hash of the signing string
  unsigned char sha256_buf[OCI_SIGNER_SHA256_DIGEST_SIZE];
  signer_params->sha256(signing_string.data, signing_string.len, sha256_buf);

  // Sign the hash with RSA
  unsigned char *signature_buf = auth_header->value.data; // we can reuse the auth header value buffer for the signature
  size_t signature_buf_size = auth_header_value_max_len;
  rc = signer_params->rsa_sign_sha256(sha256_buf, OCI_SIGNER_SHA256_DIGEST_SIZE,
                              signer_params->private_key.data, signer_params->private_key.len,
                              signature_buf, &signature_buf_size);
  if (rc != 0)
  {
    return OCI_RSA_SIGN_ERROR_BASE + rc;
  }

  // Base64 encode the signature
  unsigned char base64_signature_buf[OCI_SIGNER_BASE64_SIGNING_STRING_SIGNATURE_SIZE];
  size_t base64_signature_len = OCI_SIGNER_BASE64_SIGNING_STRING_SIGNATURE_SIZE;
  rc = signer_params->base64_encode(signature_buf, signature_buf_size,
                                   base64_signature_buf, &base64_signature_len);
  if (rc != 0)
  {
    return OCI_BASE64_ENCODE_ERROR_BASE + rc;
  }

  // Construct the Authorization header value
  unsigned char *str = auth_header->value.data;

  // Create temporary oci_signer_str_t structures for binary data
  oci_signer_str_t version_str = oci_signer_string((unsigned char *)OCI_SIGNER_VERSION);
  oci_signer_str_t algorithm_str = oci_signer_string((unsigned char *)OCI_SIGNER_SIGNING_ALGORITHM);
  oci_signer_str_t base64_signature =
  {
    .data = base64_signature_buf,
    .len = base64_signature_len
  };

  // Calculate required space for the Authorization header value
  size_t required_space = strlen("Signature version=\"\"") + version_str.len +
                         strlen(",headers=\"\"") + signing_headers.len +
                         strlen(",keyId=\"\"") + signer_params->key_id.len +
                         strlen(",algorithm=\"\"") + algorithm_str.len +
                         strlen(",signature=\"\"") + base64_signature.len;
  
  // Check for buffer overflow before writing
  if (required_space >= auth_header_value_max_len)
  {
    return OCI_SIGNER_AUTH_HEADER_BUFFER_OVERFLOW_ERROR;
  }

  // Build the Authorization header value with bounds checking
  str = oci_signer_snprintf(str, auth_header_value_max_len, "Signature version=\"%V\",headers=\"%V\",keyId=\"%V\",algorithm=\"%V\",signature=\"%V\"",
                          &version_str, &signing_headers, &signer_params->key_id, &algorithm_str, &base64_signature);

  // Set the length of the authorization header value
  auth_header->value.len = str - auth_header->value.data;

  return OCI_SIGNER_OK;
}

