# OCI Request Signer for C

This project provides a C implementation of [Oracle Cloud Infrastructure (OCI) request signature](https://docs.oracle.com/en-us/iaas/Content/API/Concepts/signingrequests.htm), suitable for use in embedded, kernel, or user-space applications. It includes a shared library and an example application demonstrating usage.

> For more background and insights about this project, see our [blog post](https://riptides.io/blog-post/announcing-oci-req-signer-c-a-lightweight-c-library-for-oracle-cloud-request-signing).

## Features

- Produces the HTTP `Authorization` header (key and value) for OCI requests, including the computed signature and all required metadata
- OCI request signing for HTTP requests
- No dynamic memory allocations
- Support for DER format private keys
- Default headers and automatic body hashing based on request method
- Simple API for integration into C projects
- Example usage and tests included
- System header configurability via `OCI_SYSTEM_HEADER`

## Building

### Prerequisites

- GCC or compatible C compiler
- `pkg-config` utility
- [OpenSSL](https://github.com/openssl/openssl) for testing and examples
- [libcheck](https://github.com/libcheck/check) for testing

### Build Instructions

```sh
sudo apt install libssl-dev check
```

To build the shared library and example application, run:

```sh
make
```

This will produce:
- `libocisigner.so`: Shared library implementing OCI request signing
- `example`: Example application using the library

### Run Tests

```sh
make run-tests
```

### Clean Build Artifacts

```sh
make clean
```

## Usage

### Private Key Format

This library **only** accepts RSA private keys in DER format. The private key is stored in a dedicated binary data type (`oci_signer_binary_t`) to clearly indicate that it contains binary data rather than a string.

If you have a PEM format key, you need to convert it to DER format before using it with this library:

```sh
# Convert PEM to DER format
openssl rsa -in private_key.pem -outform DER -out private_key.der
```

### Key ID Format

The library supports two formats for the `key_id` parameter:

1. **Standard format**: `tenancy/user/fingerprint`
   ```
   ocid1.tenancy.oc1..aaaaaaaaba3pv6wkcr4jqae5f15p2b2m2yt2j6rx32uzr4h25vqstifsfdsq/ocid1.user.oc1..aaaaaaaat5nvwcna5j6aqzjcaty5eqbb6qt2jvpkanghtgdaqedqw3rynjq/20:3b:97:13:55:1c:5b:0d:d3:37:d8:50:4e:c5:3a:34
   ```

2. **Session token format**: `ST$<user principal session token>`
   ```
   ST$aaaaaaaa7tz3aaaaaaaaaymq2maaaaaaabfwiljtdnfgqaaaa
   ```

### System Header Configurability

You can configure the system header used by the library by defining the macro `OCI_SYSTEM_HEADER` during compilation. This allows integration with custom or platform-specific headers as needed.

Example:
```sh
gcc -DOCI_SYSTEM_HEADER='<your_header.h>' ...
```

### Linking

Include the header in your application:

```c
#include "oci_signer.h"
```

Link against the shared library and OpenSSL:

```
-L. -locisigner -lssl -lcrypto
```


### Example Usage

The main output of this library is the HTTP `Authorization` header, which you add to your request:

```c
oci_signer_header_t auth_header;
// ... set up signer parameters ...
oci_signer_sign(&signer_params, &auth_header, buffer_size);
// Now add:
//   Header key:   (char*)auth_header.key.data   // will be "Authorization"
//   Header value: (char*)auth_header.value.data // contains the computed signature and metadata
```

See `example.c` for a complete usage demonstration, including examples of how to use custom crypto functions.

## Custom Crypto Implementation

For integration with custom environments (like Linux kernel modules), you can provide your own implementations of the required crypto functions:

1. Define `OCI_SYSTEM_HEADER` to include environment-specific headers instead of standard C library headers
2. Provide custom implementations of the required crypto functions:
   - SHA256 hash function
   - RSA signing function
   - Base64 encoding function

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

This implementation of computing the request authorization header is based on the [OCI Go SDK's HTTP signer](https://github.com/oracle/oci-go-sdk/blob/907df66346f4bd3b0e898b5c884422253e86cee3/common/http_signer.go#L244)
