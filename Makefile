CC       := gcc
CLANG    := clang
FLAGS    += -pipe -Wall -Wextra -Wno-unused-parameter -ggdb3
DEFINE   += -DLINUX
INCLUDE  := -I $(MUSL)/usr/include/
CFLAGS   += $(FLAGS) $(INCLUDE) $(DEFINE)
LDFLAGS  += -L/usr/local/lib
LDLIBS   := -lc -lbpf -lz -lelf
OUT      := bin

TARGETS := main-perf-event main-tc main-ringbuf xdp-tcp tc-tcp

all: dir_make $(TARGETS)

dir_make:
	test -d $(OUT) || mkdir $(OUT)

%: %.c dir_make
	$(CLANG) -O3 -g -target bpf -c $*.bpf.c -o $(OUT)/$*.bpf.o
	$(CC) $(CFLAGS) $(LDFLAGS) $*.c $(LDLIBS) -o $(OUT)/$@

clean:
	rm -rf $(OUT)

.PHONY: all clean dir_make
