all: cpustress

cpustress: cpustress.c
	gcc -I../../src -o $@ $<

clean:
	rm -rf cpustress *~

.PHONY: all clean
