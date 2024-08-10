#include <stdint.h>
#include <arpa/inet.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/icmp.h>

#include "main.h"

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 32);
    __type(key, uint32_t);
    __type(value, uint32_t);
} ping_hash SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
	__uint(key_size, sizeof(int));
	__uint(value_size, sizeof(int));
} events SEC(".maps");

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

  if (eth->h_proto != htons(ETH_P_IP)) {
    return XDP_PASS;
  }

  if (ip->protocol == 1) {
    msg.proto = 1;
    msg.saddr = ip->saddr;
    msg.daddr = ip->daddr;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));

    if (bpf_map_lookup_elem(&ping_hash, &ip->daddr) || bpf_map_lookup_elem(&ping_hash, &ip->saddr)) {
      return XDP_DROP;
    }
  }

  return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
