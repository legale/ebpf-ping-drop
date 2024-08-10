#include <arpa/inet.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

struct data_t {
    uint32_t saddr;
    uint32_t daddr;
    uint8_t proto;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} ringbuf SEC(".maps");

SEC("xdp")
int detect_tcp_syn(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    struct data_t msg = {0};
    int ret = XDP_PASS;

    struct ethhdr *eth = (struct ethhdr *)data;
    struct iphdr *ip = (struct iphdr *)((char *)data + sizeof(*eth));
    struct tcphdr *tcp = (struct tcphdr *)(ip + 1);

    // Ensure the packet has enough data to contain an Ethernet, IP, and TCP header
    if (data + sizeof(*eth) + sizeof(*ip) + sizeof(*tcp) > data_end) {
        return XDP_PASS;
    }

    // Check if the packet is an IP packet
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }

    // Check if the packet is a TCP packet
    if (ip->protocol == IPPROTO_TCP) {
        // Check if it's a SYN packet
        if (tcp->syn && !tcp->ack) {
            msg.proto = IPPROTO_TCP;
            msg.saddr = ip->saddr;
            msg.daddr = ip->daddr;

            // Send the information to the user space via the ring buffer
            bpf_ringbuf_output(&ringbuf, &msg, sizeof(msg), BPF_RB_FORCE_WAKEUP);
        }
    }

    return ret;
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
