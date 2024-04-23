all: main

main.bpf.o: main.bpf.c
	clang -O3 -g -target bpf -c main.bpf.c -o main.bpf.o

main.skel.h: main.bpf.o
	bpftool gen skeleton main.bpf.o > main.skel.h

main: main.skel.h main.c
	gcc -O3 -o main main.c -lbpf

clean:
	rm -f main.bpf.o main.skel.h main

.PHONY: all clean
