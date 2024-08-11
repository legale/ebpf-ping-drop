#include <arpa/inet.h>

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/icmp.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <stdint.h>

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

SEC("classifier")
int detect_ping(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;
  struct ethhdr *eth = data;
  struct iphdr *ip = (struct iphdr *)(eth + 1);
  struct icmphdr *icmp;

  if ((void *)(ip + 1) > data_end)
    return TC_ACT_OK;

  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  if (ip->protocol == IPPROTO_ICMP) {
    icmp = (struct icmphdr *)(ip + 1);
    if ((void *)(icmp + 1) > data_end)
      return TC_ACT_OK;

    if (icmp->type == ICMP_ECHO) {
      struct data_t msg = {.proto = 1, .saddr = ip->saddr, .daddr = ip->daddr};
      bpf_perf_event_output(skb, &events, BPF_F_CURRENT_CPU, &msg, sizeof(msg));

      uint32_t *drop = bpf_map_lookup_elem(&ping_hash, &ip->daddr);
      if (drop && *drop)
        return TC_ACT_SHOT;
    }
  }

  return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
