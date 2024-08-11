#include <arpa/inet.h>

#include <bpf/bpf.h>

#include <bpf/libbpf.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>

#include "main.h"

void handle_sigint(int sig) {
  printf("got SIGINT, stop.\n");
  exit(0);
}

static void handle_event(void *ctx, int cpu, void *data, __u32 size) {
  struct data_t *msg = data;
  char str_s[INET_ADDRSTRLEN];
  char str_d[INET_ADDRSTRLEN];
  if (inet_ntop(AF_INET, &(msg->saddr), str_s, INET_ADDRSTRLEN)) {
    printf("src ip: %s\n", str_s);
  }
  if (inet_ntop(AF_INET, &(msg->daddr), str_d, INET_ADDRSTRLEN)) {
    printf("dst ip: %s\n", str_d);
  }
}

int main(int argc, char *argv[]) {
  struct bpf_object *obj;
  struct bpf_program *prog;
  struct bpf_link *link;
  struct bpf_map *map_hash, *map_events;
  struct perf_buffer *pb;
  struct perf_buffer_opts pb_opts = {.sz = 32};

  int err;
  unsigned int ifindex;
  uint32_t ip_host, ip_server;
  const char *ip_host_str = "192.168.2.1";
  const char *ip_server_str = "8.8.8.8";

  if (argc != 2) {
    printf("interface name is required\n");
    return 1;
  }

  ifindex = if_nametoindex(argv[1]);
  signal(SIGINT, handle_sigint);

  char obj_file[PATH_MAX];
  snprintf(obj_file, sizeof(obj_file), "%s.bpf.o", argv[0]);
  printf("path: %s\n", argv[0]);

  obj = bpf_object__open(obj_file);
  if (!obj) {
    fprintf(stderr, "Failed to open BPF object file: %s\n", obj_file);
    return 1;
  }

  if (bpf_object__load(obj)) {
    fprintf(stderr, "failed to load BPF program\n");
    bpf_object__close(obj);
    return 1;
  }

  prog = bpf_object__find_program_by_name(obj, "detect_ping");
  if (!prog) {
    fprintf(stderr, "failed to find BPF program\n");
    bpf_object__close(obj);
    return 1;
  }

  link = bpf_program__attach_xdp(prog, ifindex);
  if (libbpf_get_error(link)) {
    fprintf(stderr, "failed to attach BPF program\n");
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 1;
  }

  map_events = bpf_object__find_map_by_name(obj, "events");
  if (!map_events) {
    fprintf(stderr, "failed to get events map\n");
    bpf_object__close(obj);
    return 1;
  }

  pb = perf_buffer__new(bpf_map__fd(map_events), 32, handle_event, NULL, NULL,
                        &pb_opts);
  if (!pb) {
    fprintf(stderr, "failed perf_buffer__new\n");
    bpf_object__close(obj);
    return 1;
  }

  printf("Program is running.\n");

  map_hash = bpf_object__find_map_by_name(obj, "ping_hash");
  if (!map_hash) {
    fprintf(stderr, "failed bpf_object__find_map_by_name ping_hash\n");
    bpf_object__close(obj);
    return 1;
  }

  inet_pton(AF_INET, ip_host_str, &ip_host);
  inet_pton(AF_INET, ip_server_str, &ip_server);

  err = bpf_map_update_elem(bpf_map__fd(map_hash), &ip_server, &ip_server,
                            BPF_ANY);
  if (err) {
    fprintf(stderr, "failed bpf_map_update_elem in ping_hash\n");
    bpf_object__close(obj);
    return 1;
  }

  while (1) {
    int ret = perf_buffer__poll(pb, 1000); // 1000ms timeout
    if (ret < 0) {
      fprintf(stderr, "Error polling perf buffer: %s\n", strerror(-ret));
      break;
    }
  }

  bpf_link__destroy(link);
  bpf_object__close(obj);
  return 0;
}
