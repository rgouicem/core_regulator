all: libbench.o run_rt

libbench.o: libbench.c
	$(CC) -c libbench.c

run_rt: run_rt.c
	$(CC) -I../../src -o $@ $<

clean:
	rm -rf *~ *.o run_rt

.PHONY: all clean
