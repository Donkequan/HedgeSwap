INCLUDE := include 
SRC := src
LIBS := lib
EXT_LIBS := -lgmp
BUILD_DIR = build
RP_TARGET := liblrp

.PHONY: all test clean

TARGET := ${RP_TARGET}
all: ${TARGET}

_RP_DEPS = config.h lhp.h params.h puzzle.h util.h params-rp.h
RP_DEPS = $(patsubst %,$(INCLUDE)/%,$(_RP_DEPS))

_RP_OBJ = params-rp.o proof.o prover.o verifier.o
RP_OBJ = $(patsubst %,$(BUILD_DIR)/%,$(_RP_OBJ))

CC=gcc
CFLAGS=-I ${INCLUDE} -L ${LIBS} -g

${BUILD_DIR}/%.o: ${SRC}/%.c
	$(CC) -c $< -o $@ $(CFLAGS)

${RP_TARGET}: ${RP_OBJ}
	ar rcs ${LIBS}/${RP_TARGET}.a $^

clean:
	@rm -rf ${BUILD_DIR}/*
	@rm -rf ${LIBS}/*.a

test: ${TARGET}
	make -C test/
