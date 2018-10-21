MACHINE := $(shell uname -m)

ifeq ($(MACHINE), i386)
	SRC := ax.asm
else ifeq ($(MACHINE), x86_64)
	SRC := axx.asm
else ifeq ($(MACHINE), armv7l)
	SRC := ax.s
else ifeq ($(MACHINE), aarch64)
	SRC := axx.s
endif

test:
	as $(SRC) -oax.o
	gcc -Wall -Os test.c ax.o -otest
clean:
	rm *.o test
