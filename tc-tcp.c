#include <arpa/inet.h>

#include <bpf/bpf.h>

#include <bpf/libbpf.h>
#include <errno.h>
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

  // Открытие BPF объекта
  char obj_file[PATH_MAX];
  snprintf(obj_file, sizeof(obj_file), "%s.bpf.o", argv[0]);
  printf("path: %s\n", argv[0]);

  obj = bpf_object__open(obj_file);
  if (!obj) {
    fprintf(stderr, "Failed to open BPF object file: %s\n", obj_file);
    return 1;
  }

  // Загрузка BPF программы
  if (bpf_object__load(obj)) {
    fprintf(stderr, "Failed to load BPF program\n");
    bpf_object__close(obj);
    return 1;
  }

  // Получение программы из объекта
  struct bpf_program *prog =
      bpf_object__find_program_by_name(obj, "detect_tls_client_hello");
  if (!prog) {
    fprintf(stderr, "Failed to find BPF program\n");
    bpf_object__close(obj);
    return 1;
  }

  // Привязка программы к интерфейсу с использованием TC
  struct bpf_tc_hook tc_hook = {
      .sz = sizeof(tc_hook),
      .ifindex = ifindex,
      .attach_point = BPF_TC_EGRESS // Вы можете использовать BPF_TC_INGRESS для
                                    // входящего трафика
  };

  struct bpf_tc_opts tc_opts = {
      .sz = sizeof(tc_opts),
      .prog_fd = bpf_program__fd(prog),
  };

  int ret = bpf_tc_hook_create(&tc_hook);
  if (ret && ret != -EEXIST) {
    fprintf(stderr, "Failed to create TC hook: %s\n", strerror(-ret));
    bpf_object__close(obj);
    return 1;
  }

  ret = bpf_tc_attach(&tc_hook, &tc_opts);
  if (ret) {
    fprintf(stderr, "Failed to attach TC program: %s\n", strerror(-ret));
    bpf_object__close(obj);
    return 1;
  }

  // Получение карты кольцевого буфера
  struct bpf_map *ringbuf_map = bpf_object__find_map_by_name(obj, "ringbuf");
  if (!ringbuf_map) {
    fprintf(stderr, "Failed to find ring buffer map\n");
    bpf_object__close(obj);
    return 1;
  }

  // Создание кольцевого буфера для обработки событий
  struct ring_buffer *ringbuf =
      ring_buffer__new(bpf_map__fd(ringbuf_map), handle_event, NULL, NULL);
  if (!ringbuf) {
    fprintf(stderr, "Failed to create ring buffer\n");
    bpf_object__close(obj);
    return 1;
  }

  // Получение карты для target_ip
  struct bpf_map *target_ip_map =
      bpf_object__find_map_by_name(obj, "target_ip");
  if (!target_ip_map) {
    fprintf(stderr, "Failed to find target_ip map\n");
    bpf_object__close(obj);
    return 1;
  }

  // Обновление IP-адреса цели в карте
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

  // Основной цикл
  while (running) {
    if (ring_buffer__poll(ringbuf, 100) < 0) {
      fprintf(stderr, "Error polling ring buffer\n");
      break;
    }
  }

  // Очистка ресурсов
  ring_buffer__free(ringbuf);
  bpf_tc_detach(&tc_hook, &tc_opts);
  bpf_tc_hook_destroy(&tc_hook);
  bpf_object__close(obj);
  return 0;
}
