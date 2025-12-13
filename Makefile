CC ?= gcc
AR ?= ar
OPENSSL_CFLAGS := $(shell pkg-config --cflags openssl 2>/dev/null)
OPENSSL_LIBS := $(shell pkg-config --libs openssl 2>/dev/null)

ifeq ($(strip $(OPENSSL_LIBS)),)
OPENSSL_LIBS := -lcrypto -lssl
endif

CFLAGS ?= -O2
CFLAGS += -Wall -Wextra -pedantic -std=c11 -D_POSIX_C_SOURCE=200809L -ISIG_AS/common $(OPENSSL_CFLAGS)
LDFLAGS += $(OPENSSL_LIBS)

BUILD_DIR := SIG_AS/build
SIG_TARGET := $(BUILD_DIR)/sig_as

SIG_SRCS := SIG_AS/test.c SIG_AS/ecdsa.c SIG_AS/schnorr.c
SIG_OBJS := $(patsubst %.c,$(BUILD_DIR)/%.o,$(SIG_SRCS))

.PHONY: all clean run-ds run-schnorr run-ecdsa run-vtd

all: $(SIG_TARGET)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)/SIG_AS

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@


$(SIG_TARGET): $(SIG_OBJS)
	$(CC) $^ -o $@ $(LDFLAGS)

run-ds: $(SIG_TARGET)
	./$(SIG_TARGET)

run-schnorr: $(SIG_TARGET)
	./$(SIG_TARGET) schnorr

run-ecdsa: $(SIG_TARGET)
	./$(SIG_TARGET) ecdsa

run-vtd:
	$(MAKE) -C VTD/VTD test

clean:
	rm -rf $(BUILD_DIR)
