// go:build ignore

#include "vmlinux.h"

// clang-format off
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#include "ulogf.h"
#include "utils.h"

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 16);
} tx_bytes_per_sec SEC(".maps");

SEC("lwt_xmit/test_data")
int do_test_data(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ipv6hdr *ip6h = data;
  if (data + sizeof(*ip6h) > data_end) {
    bpf_printk("packet truncated");
    return BPF_DROP;
  }

  ulogf("Packet: src=%pI6, dst=%pI6", (u64)&ip6h->saddr, (u64)&ip6h->daddr);

  // read and log tx bytes
  u32 key = skb->ifindex;
  ulogf("ifindex=%u", key);
  u64 *tx_bytes = bpf_map_lookup_elem(&tx_bytes_per_sec, &key);
  if (tx_bytes) ulogf("tx_bytes=%llu", *tx_bytes);

  u16 func = SID_FUNC(&ip6h->daddr);
  u64 arg = SID_ARG(&ip6h->daddr);

  if (func == 0x8000) {
    // check if payload has SRv6 header
    if (ip6h->nexthdr == IPPROTO_ROUTING) {
      struct ipv6_sr_hdr *sr_hdr = (struct ipv6_sr_hdr *)(ip6h + 1);

      if ((void *)(sr_hdr + 1) > data_end) {
        bpf_printk("packet truncated");
        return BPF_DROP;
      }
      // check if the type is SRH
      if (sr_hdr->type != 4) return BPF_DROP;

      ulogf("SRH found: func=%04x, arg=%012x", func, arg);

      if (sr_hdr->segments_left == 0) return BPF_DROP;
      u8 new_segments_left = sr_hdr->segments_left - 1;
      struct in6_addr *new_dst_ptr = sr_hdr->segments + new_segments_left;

      if ((void *)(new_dst_ptr + 1) > data_end) {
        bpf_printk("packet truncated");
        return BPF_DROP;
      }

      struct in6_addr new_dst = *new_dst_ptr;
      ulogf("Dst updated: new_dst=%pI6", (u64)&new_dst);

      bpf_skb_store_bytes(skb, offsetof(struct ipv6hdr, daddr), &new_dst, 16,
                          0);
      bpf_skb_store_bytes(
          skb,
          sizeof(struct ipv6hdr) + offsetof(struct ipv6_sr_hdr, segments_left),
          &new_segments_left, 1, 0);
      return BPF_LWT_REROUTE;
    }
  }

  return BPF_OK;
}

char _license[] SEC("license") = "GPL";
