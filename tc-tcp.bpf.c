#include <arpa/inet.h>

#include <linux/bpf.h>

#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, __u32);
} target_ip SEC(".maps");

struct event_t {
  __u32 src_ip;
  __u32 dst_ip;
  __u16 src_port;
  __u16 dst_port;
};

static __always_inline int is_tls_client_hello(void *data, void *data_end) {
  __u8 *payload = data;
  if (payload + 6 > (__u8 *)data_end)
    return 0;

  // Check for TLS record layer
  if (payload[0] != 0x16) // Handshake
    return 0;

  // Check TLS version (1.0, 1.1, 1.2)
  if (payload[1] != 0x03 ||
      (payload[2] != 0x01 && payload[2] != 0x02 && payload[2] != 0x03))
    return 0;

  // Check handshake type
  if (payload[5] != 0x01) // Client Hello
    return 0;

  return 1;
}

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

SEC("tc")
int detect_tls_client_hello(struct __sk_buff *skb) {
  void *data_end = (void *)(long)skb->data_end;
  void *data = (void *)(long)skb->data;

  struct ethhdr *eth = data;

  if ((void *)(eth + 1) > data_end) {
    bpf_printk("%d ETH layer check failed\n", __LINE__);
    return TC_ACT_OK;
  }

  if (eth->h_proto != bpf_htons(ETH_P_IP)) {
    print_mac_info(__LINE__, eth, "Non-IP packet");
    return TC_ACT_OK;
  }

  struct iphdr *iph = (void *)(eth + 1);

  if ((void *)(iph + 1) > data_end) {
    print_mac_info(__LINE__, eth, "IP header check failed");
    return TC_ACT_OK;
  }

  if (iph->protocol != IPPROTO_TCP) {
    print_mac_info(__LINE__, eth, "Non-TCP packet");
    return TC_ACT_OK;
  }

  struct tcphdr *tcph = (void *)(iph + 1);
  if ((void *)(tcph + 1) > data_end) {
    print_mac_info(__LINE__, eth, "TCP header check failed");
    return TC_ACT_OK;
  }

  struct event_t event;
  event.src_ip = iph->saddr;
  event.dst_ip = iph->daddr;
  event.src_port = bpf_ntohs(tcph->source);
  event.dst_port = bpf_ntohs(tcph->dest);

  if (event.dst_port != 443 && event.src_port != 443) {
    print_mac_info(__LINE__, eth, "Non-443 port packet");
    return TC_ACT_OK;
  }

  __u32 key = 0;
  __u32 *target_ip_ptr = bpf_map_lookup_elem(&target_ip, &key);

  if (!target_ip_ptr) {
    print_mac_info(__LINE__, eth, "Target IP lookup failed");
    return TC_ACT_OK;
  }

  if (iph->saddr != *target_ip_ptr && iph->daddr != *target_ip_ptr) {
    print_mac_info(__LINE__, eth, "IP address doesn't match target");
    return TC_ACT_OK;
  }

  bpf_ringbuf_output(&ringbuf, &event, sizeof(event), 0);

  // Calculate the TCP header length
  __u8 tcp_header_len = (tcph->doff & 0xf) * 4;
  void *payload = (void *)tcph + tcp_header_len;

  if (payload + 6 > data_end) {
    print_mac_info(__LINE__, eth, "Payload bounds check failed");
    return TC_ACT_OK;
  }

  if (!is_tls_client_hello(payload, data_end)) {
    print_mac_info(__LINE__, eth, "Not a TLS Client Hello packet");
    return TC_ACT_OK;
  }

  bpf_ringbuf_output(&ringbuf, &event, sizeof(event), 0);

  return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
