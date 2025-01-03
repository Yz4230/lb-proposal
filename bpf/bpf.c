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
} bw_bits_per_sec SEC(".maps");

#ifdef DISABLE_ULOGF
#ifdef ulogf
#undef ulogf
#define ulogf(fmt, ...) ({})
#endif
#endif

SEC("lwt_xmit/proposal")
int do_proposal(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ipv6hdr *ip6h = data;
  if (data + sizeof(*ip6h) > data_end) {
    bpf_printk("packet truncated");
    return BPF_DROP;
  }

  ulogf("Packet: src=%pI6, dst=%pI6", (u64)&ip6h->saddr, (u64)&ip6h->daddr);

  if (ip6h->nexthdr != IPPROTO_ROUTING) return BPF_OK;  // 43: Routing Header
  struct ipv6_sr_hdr *sr_hdr = (struct ipv6_sr_hdr *)(ip6h + 1);
  if ((void *)(sr_hdr + 1) > data_end) return BPF_DROP;
  if (sr_hdr->type != 4) return BPF_DROP;  // 4: Segment Routing Header

  u16 func = SID_FUNC(&ip6h->daddr);
  u64 arg = SID_ARG(&ip6h->daddr);

  if (func == 0x8000) {  // skip_segments_if
    // 8 8 8 8 16
    // skip_num metrics comparator nic_index bps
    u8 num_skip = (arg >> 40) & 0xff;
    u8 metrics = (arg >> 32) & 0xff;
    u8 comparator = (arg >> 24) & 0xff;
    u8 nic_index = (arg >> 16) & 0xff;
    u16 mega_bits_per_sec = arg & 0xffff;
    ulogf(
        "SRH found: func=%04x, skip_num=%u, metrics=%u, comparator=%u, "
        "nic_index=%u, bps=%u",
        func, num_skip, metrics, comparator, nic_index, mega_bits_per_sec);

    bool match = false;
    if (metrics == 0) {
      u64 key = nic_index;
      u64 *metrics_value = bpf_map_lookup_elem(&bw_bits_per_sec, &key);
      if (!metrics_value) {
        ulogf("metrics not found: nic_index=%u", nic_index);
        return BPF_DROP;
      }
      if (comparator == 0)
        match = (*metrics_value == mega_bits_per_sec);
      else if (comparator == 1)
        match = (*metrics_value > mega_bits_per_sec);
      else if (comparator == 2)
        match = (*metrics_value < mega_bits_per_sec);
      ulogf("match=%d, matrics_value=%llu, bps=%u", match, *metrics_value,
            mega_bits_per_sec);
    }

    if (sr_hdr->segments_left == 0) return BPF_DROP;
    u8 new_segments_left = sr_hdr->segments_left - 1;
    bool should_decap = false;
    if (match) {
      if (new_segments_left >= num_skip) {
        new_segments_left -= num_skip;
      } else {
        should_decap = true;
      }
    };

    if (should_decap) {
      // // decap the SRH
      // if ((void *)(sr_hdr->segments + 1) > data_end) return BPF_DROP;
      // // struct in6_addr localhost = {.in6_u.u6_addr32 = {0, 0, 0, 1}};
      // // fc00:a:12:0:0001::
      // struct in6_addr seg6_end = {.in6_u.u6_addr8 = {
      //                                 // clang-format off
      //   0xfc, 0x00, 0x00, 0x0a, 0x00, 0x00, 0x00, 0x12,
      //   0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      //                                 // clang-format on
      //                             }};
      // ip6h->daddr = seg6_end;
      // sr_hdr->segments[0] = seg6_end;
      // sr_hdr->segments_left = 0;
      return BPF_DROP;
    } else {
      struct in6_addr *new_dst_ptr = sr_hdr->segments + new_segments_left;
      if ((void *)(new_dst_ptr + 1) > data_end) return BPF_DROP;
      ip6h->daddr = *new_dst_ptr;
      sr_hdr->segments_left = new_segments_left;
    }
    ulogf("Dst updated: new_dst=%pI6", (u64)&ip6h->daddr);

    return BPF_LWT_REROUTE;
  } else if (func == 0x8001) {  // just_skip_segments
    // 8 40
    // skip_num (zero)
    u8 num_skip = (arg >> 40) & 0xff;
    ulogf("SRH found: func=%04x, skip_num=%u", func, num_skip);

    if (sr_hdr->segments_left == 0) return BPF_DROP;
    u8 new_segments_left = sr_hdr->segments_left - 1;
    bool should_decap = false;
    if (new_segments_left >= num_skip) {
      new_segments_left -= num_skip;
    } else {
      should_decap = true;
    }

    if (should_decap) {
      // not support decap
      return BPF_DROP;
    } else {
      struct in6_addr *new_dst_ptr = sr_hdr->segments + new_segments_left;
      if ((void *)(new_dst_ptr + 1) > data_end) return BPF_DROP;
      ip6h->daddr = *new_dst_ptr;
      sr_hdr->segments_left = new_segments_left;
    }
    ulogf("Dst updated: new_dst=%pI6", (u64)&ip6h->daddr);

    return BPF_LWT_REROUTE;
  }

  return BPF_OK;
}

char _license[] SEC("license") = "GPL";
