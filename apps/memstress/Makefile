all:

routines-x86-64bit.o: routines-x86-64bit.asm
	nasm -f elf64 $< -o $@

x86: memstress.c memstress_rt.c memstress_slow.c routines-x86-64bit.o
#	$(CC) memstress_rt.c routines-x86-64bit.o $(LIBBENCH) -o memstress_rt
#	$(CC) memstress.c routines-x86-64bit.o $(LIBBENCH) -o memstress
	$(CC) memstress_slow.c routines-x86-64bit.o $(LIBBENCH) -o memstress

arm: memstress.c memstress_rt.c memstress_slow.c memstress_rt_sabre.c routines-arm-32bit.S
#	$(CC) memstress_rt.c routines-arm-32bit.S $(LIBBENCH) -o memstress_rt
#	$(CC) memstress.c routines-arm-32bit.S $(LIBBENCH) -o memstress
	$(CC) -O3 memstress_slow.c routines-arm-32bit.S $(LIBBENCH) -o memstress
#	$(CC) memstress_rt_sabre.c routines-arm-32bit.S $(LIBBENCH) -o memstress_rt_sabre

clean:
	rm -rf *.o *~
	rm -f memstress #memstress_slow memstress_rt memstress_rt_sabre

.PHONY: all clean mrproper x86 arm
