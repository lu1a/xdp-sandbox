#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <bpf/bpf_helpers.h>

struct packet_info {
    __u32 pkt_len;
    __u8 data[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} packet_ringbuf SEC(".maps");

SEC("xdp")
int xdp_packet_logger(struct xdp_md *ctx) {
    void *data_end = (void *)(unsigned long)ctx->data_end;
    void *data = (void *)(unsigned long)ctx->data;
    struct ethhdr *eth = data;

    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;

    struct packet_info *pkt_info = bpf_ringbuf_reserve(&packet_ringbuf, sizeof(*pkt_info), 0);
    if (!pkt_info)
        return XDP_DROP;

    pkt_info->pkt_len = (__u32)((unsigned long)data_end - (unsigned long)data);

    __u64 pkt_size = pkt_info->pkt_len < sizeof(pkt_info->data) ? pkt_info->pkt_len : sizeof(pkt_info->data);
    bpf_probe_read_kernel(pkt_info->data, pkt_size, data);

    bpf_ringbuf_submit(pkt_info, 0);
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";
