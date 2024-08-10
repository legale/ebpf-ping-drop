#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/limits.h> //PATH_MAX
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <libgen.h> // basename и dirname

#include "main.h"

void handle_sigint(int sig)
{
    printf("got SIGINT, stop.\n");
    exit(0);
}

int handle_event(void *ctx, void *data, size_t len)
{
    struct data_t *msg = (struct data_t *)data;
    char str_s[INET_ADDRSTRLEN];
    char str_d[INET_ADDRSTRLEN];
    printf("--- got TCP SYN! ---\n");
    if (inet_ntop(AF_INET, &(msg->saddr), str_s, INET_ADDRSTRLEN))
    {
        printf("src ip: %s\n", str_s);
    }
    if (inet_ntop(AF_INET, &(msg->daddr), str_d, INET_ADDRSTRLEN))
    {
        printf("dst ip: %s\n", str_d);
    }
    return 0;
}

int main(int argc, char *argv[])
{
    struct bpf_object *obj;
    struct bpf_program *prog;
    struct bpf_link *link;
    struct bpf_map *ringbuf_map;
    struct ring_buffer *ringbuf;
    unsigned int ifindex;

    if (argc != 2)
    {
        printf("interface name is required\n");
        return 1;
    }

    ifindex = if_nametoindex(argv[1]);
    signal(SIGINT, handle_sigint);

    char obj_file[PATH_MAX];

    // Получаем путь и имя исполняемого файла, добавляем расширение .bpf.o
    snprintf(obj_file, sizeof(obj_file), "%s/%s.bpf.o", dirname(argv[0]), basename(argv[0]));
    printf("argv[0]: %s\n", argv[0]);
    printf("obj: %s\n", obj_file);
    printf("argv[0] dirname: %s\n", dirname(argv[0]));

    // Открытие BPF программы
    obj = bpf_object__open(obj_file);
    if (!obj)
    {
        fprintf(stderr, "Failed to open BPF object file: %s\n", obj_file);
        return 1;
    }

    if (bpf_object__load(obj))
    {
        fprintf(stderr, "failed to load BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    prog = bpf_object__find_program_by_name(obj, "detect_tcp_syn");
    if (!prog)
    {
        fprintf(stderr, "failed to find BPF program\n");
        bpf_object__close(obj);
        return 1;
    }

    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link))
    {
        fprintf(stderr, "failed to attach BPF program\n");
        bpf_link__destroy(link);
        bpf_object__close(obj);
        return 1;
    }

    ringbuf_map = bpf_object__find_map_by_name(obj, "ringbuf");
    if (!ringbuf_map)
    {
        fprintf(stderr, "failed to get ring buffer map\n");
        bpf_object__close(obj);
        return 1;
    }

    ringbuf = ring_buffer__new(bpf_map__fd(ringbuf_map), handle_event, NULL, NULL);
    if (!ringbuf)
    {
        fprintf(stderr, "failed to create ring buffer\n");
        bpf_object__close(obj);
        return 1;
    }

    printf("Program is running.\n");

    while (1)
    {
        if (ring_buffer__poll(ringbuf, 1000) < 0)
        {
            fprintf(stderr, "error polling ring buffer\n");
            break;
        }
    }

    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 0;
}
