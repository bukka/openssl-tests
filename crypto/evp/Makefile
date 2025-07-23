# List of OpenSSL versions
OPENSSL_VERSIONS := ssl30 ssl31 ssl32 ssl33 ssl34 ssl35 sslmaster

# Default OpenSSL version if not specified
DEFAULT_VERSION := ssl35

# Programs to compile
PROGRAMS := ocb dh-gen

# Source files (assumed to have one .c file per program)
SRCS := $(patsubst %,%.c,$(PROGRAMS))

# Compiler and flags
CC := gcc
CFLAGS := -Wall -Wextra

# Get the selected OpenSSL version (or use default)
OPENSSL_VERSION := $(or $(VERSION),$(DEFAULT_VERSION))

# OpenSSL paths
OPENSSL_PREFIX := /usr/local/$(OPENSSL_VERSION)
PKG_CONFIG_PATH := $(OPENSSL_PREFIX)/lib64/pkgconfig
LD_LIBRARY_PATH := $(OPENSSL_PREFIX)/lib64

# Set OpenSSL library and include paths using pkg-config
OPENSSL_CFLAGS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --cflags openssl)
OPENSSL_LIBS := $(shell PKG_CONFIG_PATH=$(PKG_CONFIG_PATH) pkg-config --libs openssl)

# Target to build all programs
all: $(PROGRAMS)

# Rule to compile each program individually
%: %.c
	$(CC) $(CFLAGS) $(OPENSSL_CFLAGS) -o $@ $< $(OPENSSL_LIBS)

# Target to run all programs
run: $(PROGRAMS)
	@for prog in $(PROGRAMS); do \
		echo "Running $$prog..."; \
		LD_LIBRARY_PATH=$(LD_LIBRARY_PATH) ./$$prog; \
	done

# Clean target
clean:
	rm -f $(PROGRAMS)

# Help target to list OpenSSL versions
help:
	@echo "Usage: make [VERSION=<version>] [target]"
	@echo "Available OpenSSL versions:"
	@echo "$(OPENSSL_VERSIONS)"
	@echo "Available programs: $(PROGRAMS)"

.PHONY: clean run help
