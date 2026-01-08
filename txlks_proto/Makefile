CC ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic

OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS   := $(shell pkg-config --libs openssl 2>/dev/null)

SRC_COMMON = common.c txlks.c tinymt32.c xsadd.c

all: client server

client: client.c $(SRC_COMMON)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -I. -o $@ $^ $(OPENSSL_LIBS)

server: server.c $(SRC_COMMON)
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -I. -o $@ $^ $(OPENSSL_LIBS)

clean:
	rm -f client server
