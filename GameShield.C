#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>

#define FIVEM_PORT 30120
#define MAX_PKT_RATE 500

struct bpf_map_def SEC("maps") ip_counter = {
    .type = BPF_MAP_TYPE_HASH,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u64),
    .max_entries = 10240,
};

SEC("xdp")
int xdp_fivem_ddos_shield(struct xdp_md *ctx) {
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;

    struct ethhdr *eth = data;
    if ((void *)eth + sizeof(*eth) > data_end)
        return XDP_PASS;

    if (eth->h_proto != __constant_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = data + sizeof(*eth);
    if ((void *)ip + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (ip->protocol != IPPROTO_UDP)
        return XDP_PASS;

    struct udphdr *udp = (void *)ip + ip->ihl * 4;
    if ((void *)udp + sizeof(*udp) > data_end)
        return XDP_PASS;

    __u16 dst_port = ntohs(udp->dest);
    if (dst_port != FIVEM_PORT)
        return XDP_PASS;

    // Drop tiny UDP payloads
    if (ntohs(udp->len) < 8)
        return XDP_DROP;

    // Rate limit per IP
    __u32 src_ip = ip->saddr;
    __u64 *count = bpf_map_lookup_elem(&ip_counter, &src_ip);
    __u64 new_count = 1;
    if (count) {
        new_count = *count + 1;
        if (new_count > MAX_PKT_RATE)
            return XDP_DROP;
    }
    bpf_map_update_elem(&ip_counter, &src_ip, &new_count, BPF_ANY);

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
