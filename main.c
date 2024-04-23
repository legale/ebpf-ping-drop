#include <stdio.h>
#include <stdlib.h>
#include <signal.h>
#include <linux/bpf.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <net/if.h>

#include "main.h"
#include "main.skel.h"


void handle_sigint(int sig) {
    printf("got SIGINT, stop.\n");
    exit(0);
}


int handle_event(void *ctx, void *data, size_t len)  {
    struct data_t *msg = (struct data_t *)data;
    char str_s[INET_ADDRSTRLEN];
    char str_d[INET_ADDRSTRLEN];
    printf("--- got ping! ---\n");
    if (inet_ntop(AF_INET, &(msg->saddr), str_s, INET_ADDRSTRLEN)) {
        printf("src ip: %s\n", str_s);
    }
    if (inet_ntop(AF_INET, &(msg->daddr), str_d, INET_ADDRSTRLEN)) {
        printf("dst ip: %s\n", str_d);
    }
    return 0;
}

int main(int argc, char *argv[]) {
    int err;
    unsigned int ifindex;

    if (argc != 2) {
       printf("interface name is required\n");
       return 1; 
    }

    /* Attach BPF to network interface */
    ifindex = if_nametoindex(argv[1]);

    // Set up signal handler to exit
    signal(SIGINT, handle_sigint);

    // Load and verify BPF application
    struct main_bpf *skel = main_bpf__open_and_load();
    if (!skel) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        return 1;
    }

    // attach xdp program to interface
    struct bpf_link *link = bpf_program__attach_xdp(skel->progs.detect_ping, ifindex);
    if (!link) {
        fprintf(stderr, "bpf_program__attach_xdp\n");
        return 1;
    }

    struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(skel->obj, "ringbuf");
    if (!ringbuf_map)
    {
        fprintf(stderr, "failed to get ring buffer map\n");
        return 1;
    }

    struct ring_buffer *ringbuf = ring_buffer__new(bpf_map__fd(ringbuf_map), handle_event, NULL, NULL);
    if (!ringbuf)
    {
        fprintf(stderr, "failed to create ring buffer\n");
        return 1;
    }



    printf("Program is running.\n");


    struct bpf_map *map_hash = bpf_object__find_map_by_name(skel->obj, "ping_hash");
    if (!map_hash) {
        fprintf(stderr, "!map_hash\n");
        return 1;
    }

    const char* ip_host_str = "192.168.2.1";
    uint32_t ip_host;
    inet_pton(AF_INET, ip_host_str, &ip_host);

    const char* ip_server_str = "8.8.8.8";
    uint32_t ip_server;
    inet_pton(AF_INET, ip_server_str, &ip_server);

    err = bpf_map__update_elem(map_hash, &ip_server, sizeof(uint32_t), &ip_server, sizeof(uint32_t), BPF_ANY);
    if (err) {
        fprintf(stderr, "failed to update element in ping_hash\n");
        return 1;
    }

    // Poll the ring buffer
    while (1)
    {
        if (ring_buffer__poll(ringbuf, 1000 /* timeout, ms */) < 0)
        {
            fprintf(stderr, "error polling ring buffer\n");
            break;
        }
    }

    return 0;
}
