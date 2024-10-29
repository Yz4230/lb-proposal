// go:build ignore

#include "vmlinux.h"

// clang-format off
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// clang-format on

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} tx_bytes_per_sec SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 128);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} log_entries SEC(".maps");

// IPv6 Routing header
#define IPPROTO_ROUTING 43
#define ntohll(x) (((u64)bpf_ntohl(x)) << 32) + bpf_ntohl(x >> 32)
#define SID_FUNC(x) bpf_ntohs(*((u16 *)(x) + 4))
#define SID_ARG(x) ntohll(*((u64 *)(x) + 1)) & 0x0000FFFFFFFFFFFF

// ユーザー空間にログを出力するための関数
// Note: 引数はu64型にキャストされている必要がある
#define ulogf(fmt, args...)                                                    \
  ({                                                                           \
    static const char _fmt[] = fmt;                                            \
    static char _buf[256];                                                     \
    u64 _args[___bpf_narg(args)];                                              \
    ___bpf_fill(_args, args);                                                  \
    int _len = bpf_snprintf(_buf, sizeof(_buf), _fmt, _args, sizeof(_args));   \
    if (_len < sizeof(_buf)) {                                                 \
      bpf_perf_event_output(skb, &log_entries, BPF_F_CURRENT_CPU, _buf, _len); \
    }                                                                          \
  })

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
