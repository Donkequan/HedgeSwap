INCLUDE := ../include
LIBS := ../lib
EXT_LIBS := -lvtd -llrp -llhp -lgmp -lpbc -lssl -lcrypto

CC=gcc
CFLAGS=-I ${INCLUDE} -L ${LIBS} ${EXT_LIBS} -g

.PHONY: test clean

./%.o: %.c
	@$(CC) $^ -o $@ $(CFLAGS)

./%.test: %.o
	@echo "-----------------------------"
	@echo "Running `basename $^ .o`"
	@echo "-----------------------------"
	@./$^
	@echo "============================="

test: timecode.test

clean: 
	@rm -rf ./*.o
