# Makefile for OCI Request Signer C implementation

CC = gcc
CFLAGS = -Wall -g -Wextra -std=c99 -fPIC $(shell pkg-config --cflags libssl)
LIB_NAME = liboci_signer.so
LIB_SRC = oci_signer.c
LIB_HDR = oci_signer.h
EXAMPLE_SRC = example.c
EXAMPLE_BIN = example
TEST_SRC = test.c
TEST_BIN = test
OPENSSL_LIBS = $(shell pkg-config --libs libssl,libcrypto)
CHECK_LIBS = $(shell pkg-config --libs check)

all: $(LIB_NAME) $(EXAMPLE_BIN)

$(LIB_NAME): $(LIB_SRC) $(LIB_HDR)
	$(CC) $(CFLAGS) -shared -o $@ $(LIB_SRC) $(OPENSSL_LIBS)

$(EXAMPLE_BIN): $(EXAMPLE_SRC) $(LIB_NAME)
	$(CC) -Wall -Wextra -std=c99 $(shell pkg-config --cflags libssl) -o $@ $(EXAMPLE_SRC) -L. -loci_signer $(OPENSSL_LIBS)

$(TEST_BIN): $(TEST_SRC) $(LIB_NAME)
	$(CC) -Wall -g -Wextra -std=c99 $(shell pkg-config --cflags libssl,check) -o $@ $(TEST_SRC) -L. -loci_signer $(OPENSSL_LIBS) $(CHECK_LIBS)

run-tests: $(TEST_BIN)
	LD_LIBRARY_PATH=. ./$(TEST_BIN)

run-example: $(EXAMPLE_BIN)
	LD_LIBRARY_PATH=. ./$(EXAMPLE_BIN)

clean:
	rm -f $(LIB_NAME) $(EXAMPLE_BIN) $(TEST_BIN) *.o