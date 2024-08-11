#include <arpa/inet.h>

#include <bpf/bpf.h>

#include <bpf/libbpf.h>
#include <errno.h>
#include <libgen.h>
#include <linux/bpf.h>
#include <linux/limits.h>
#include <net/if.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

struct event_t {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
};

static int running = 1;

void handle_sigint(int sig) {
  printf("Received SIGINT, stopping...\n");
  running = 0;
}

int handle_event(void *ctx, void *data, size_t len) {
  struct event_t *event = (struct event_t *)data;
  char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];

  inet_ntop(AF_INET, &event->src_ip, src_ip, INET_ADDRSTRLEN);
  inet_ntop(AF_INET, &event->dst_ip, dst_ip, INET_ADDRSTRLEN);

  printf("Detected TLS Client Hello:\n");
  printf("  Source IP:Port: %s:%u\n", src_ip, event->src_port);
  printf("  Destination IP:Port: %s:%u\n", dst_ip, event->dst_port);

  return 0;
}

int main(int argc, char *argv[]) {
  struct bpf_object *obj;

  if (argc != 3) {
    fprintf(stderr, "Usage: %s <interface> <target_ip>\n", argv[0]);
    return 1;
  }

  char *interface = argv[1];
  char *target_ip_str = argv[2];
  unsigned int ifindex = if_nametoindex(interface);
  if (ifindex == 0) {
    fprintf(stderr, "Failed to get interface index for %s\n", interface);
    return 1;
  }

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
    fprintf(stderr, "Failed to load BPF program\n");
    bpf_object__close(obj);
    return 1;
  }

  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "detect_tls_client_hello");
  if (!prog) {
    fprintf(stderr, "Failed to find BPF program\n");
    bpf_object__close(obj);
    return 1;
  }

  struct bpf_link *link = bpf_program__attach_xdp(prog, ifindex);
  if (libbpf_get_error(link)) {
    fprintf(stderr, "Failed to attach BPF program\n");
    bpf_link__destroy(link);
    bpf_object__close(obj);
    return 1;
  }

  struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(obj, "ringbuf");
  if (!ringbuf_map) {
    fprintf(stderr, "Failed to find ring buffer map\n");
    bpf_object__close(obj);
    return 1;
  }

  struct ring_buffer *ringbuf =
      ring_buffer__new(bpf_map__fd(ringbuf_map), handle_event, NULL, NULL);
  if (!ringbuf) {
    fprintf(stderr, "Failed to create ring buffer\n");
    bpf_object__close(obj);
    return 1;
  }

  struct bpf_map *target_ip_map =
      bpf_object__find_map_by_name(obj, "target_ip");
  if (!target_ip_map) {
    fprintf(stderr, "Failed to find target_ip map\n");
    bpf_object__close(obj);
    return 1;
  }

  __u32 key = 0;
  __u32 target_ip = inet_addr(target_ip_str);
  int map_fd = bpf_map__fd(target_ip_map);
  if (map_fd < 0) {
    fprintf(stderr, "Failed to get file descriptor for target_ip map\n");
    bpf_object__close(obj);
    return 1;
  }

  if (bpf_map_update_elem(map_fd, &key, &target_ip, BPF_ANY)) {
    fprintf(stderr, "Failed to update target IP in map: %s\n", strerror(errno));
    bpf_object__close(obj);
    return 1;
  }

  printf("Program is running. Monitoring TLS Client Hello packets for IP: %s\n",
         target_ip_str);

  while (running) {
    if (ring_buffer__poll(ringbuf, 100) < 0) {
      fprintf(stderr, "Error polling ring buffer\n");
      break;
    }
  }

  ring_buffer__free(ringbuf);
  bpf_link__destroy(link);
  bpf_object__close(obj);
  return 0;
}