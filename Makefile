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

VTD_ROOT := VTD
VTD_TIME_PUZZLES := $(VTD_ROOT)/time-puzzles
VTD_RANGE_PROOF := $(VTD_ROOT)/range-proof
VTD_CORE := $(VTD_ROOT)/VTD
VTD_CORE_LIB := $(VTD_CORE)/lib

LHP_SRC := $(VTD_TIME_PUZZLES)/lib/liblhp.a
LRP_SRC := $(VTD_RANGE_PROOF)/lib/liblrp.a
LHP_DST := $(VTD_CORE_LIB)/liblhp.a
LRP_DST := $(VTD_CORE_LIB)/liblrp.a

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

run-vtd: $(LHP_DST) $(LRP_DST)
	mkdir -p $(VTD_CORE)/build $(VTD_CORE_LIB)
	$(MAKE) -C $(VTD_CORE) test

$(LHP_SRC):
	mkdir -p $(VTD_TIME_PUZZLES)/build $(VTD_TIME_PUZZLES)/lib
	$(MAKE) -C $(VTD_TIME_PUZZLES)

$(LRP_SRC):
	mkdir -p $(VTD_RANGE_PROOF)/build $(VTD_RANGE_PROOF)/lib
	$(MAKE) -C $(VTD_RANGE_PROOF)

$(LHP_DST): $(LHP_SRC)
	mkdir -p $(VTD_CORE_LIB)
	cp $< $@

$(LRP_DST): $(LRP_SRC)
	mkdir -p $(VTD_CORE_LIB)
	cp $< $@

clean:
	rm -rf $(BUILD_DIR)
