# this Makefile is only used for Github CodeQL to analyze C code

all:
	make -C cydrogen -f Makefile.fake $@

clean:
	rm -f cydrogen/cyutils.o cydrogen/src/hydrogen.o

.PHONY: all clean
