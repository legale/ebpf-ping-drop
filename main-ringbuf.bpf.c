#include <arpa/inet.h>

#include <linux/bpf.h>

#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <stdint.h>

#include "main.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, uint32_t);
  __type(value, uint32_t);
} ping_hash SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

static __always_inline void print_mac_info(int line, const struct ethhdr *eth,
                                           const char *msg) {
  bpf_printk("Line %d: %s\n", line, msg);
  bpf_printk("src_mac=%02x:%02x:%02x:%02x:%02x:%02x, "
             "dst_mac=%02x:%02x:%02x:%02x:%02x:%02x\n",
             eth->h_source[0], eth->h_source[1], eth->h_source[2],
             eth->h_source[3], eth->h_source[4], eth->h_source[5],
             eth->h_dest[0], eth->h_dest[1], eth->h_dest[2], eth->h_dest[3],
             eth->h_dest[4], eth->h_dest[5]);
}

SEC("xdp")
int detect_ping(struct xdp_md *ctx) {
  void *data_end = (void *)(long)ctx->data_end;
  void *data = (void *)(long)ctx->data;
  struct data_t msg = {0};
  int ret = XDP_PASS;

  struct ethhdr *eth = (struct ethhdr *)data;
  struct iphdr *ip = (struct iphdr *)((char *)data + sizeof(*eth));
  struct icmphdr *icmp = (struct icmphdr *)(ip + 1);

  if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*icmp) > data_end) {
    return XDP_PASS;
  }
  print_mac_info(__LINE__, eth, "bpf_trace_printk");

  if (ip->protocol == 1) {
    msg.proto = 1;
    msg.saddr = ip->saddr;
    msg.daddr = ip->daddr;

    bpf_ringbuf_output(&ringbuf, &msg, sizeof(msg), BPF_RB_FORCE_WAKEUP);

    if (bpf_map_lookup_elem(&ping_hash, &ip->daddr) ||
        bpf_map_lookup_elem(&ping_hash, &ip->saddr)) {
      return XDP_DROP;
    }
  }

  return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
