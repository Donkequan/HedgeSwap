INCLUDE := include 
SRC := src
LIBS := lib
EXT_LIBS := -lgmp
BUILD_DIR = build
VTD_TARGET := libvtd

.PHONY: all test clean

TARGET := ${VTD_TARGET}
all: ${TARGET}

_VTD_DEPS = config.h lhp.h params.h puzzle.h util.h config.h vtd.h verifier.h
VTD_DEPS = $(patsubst %,$(INCLUDE)/%,$(_VTD_DEPS))

_VTD_OBJ = vtd.o 
VTD_OBJ = $(patsubst %,$(BUILD_DIR)/%,$(_VTD_OBJ))

CC=gcc 
CFLAGS=-I ${INCLUDE} -L ${LIBS} -g

${BUILD_DIR}/%.o: ${SRC}/%.c
	@mkdir -p $(dir $@)
	$(CC) -c $< -o $@ $(CFLAGS)

${VTD_TARGET}: ${VTD_OBJ}
	@mkdir -p ${LIBS}
	ar rcs ${LIBS}/${VTD_TARGET}.a $^

clean:
	@rm -rf ${BUILD_DIR}/*
	@rm -rf ${LIBS}/*.a

test: ${TARGET}
	make -C test/ 
