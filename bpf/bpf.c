// go:build ignore

#include "net_shared.h"
#include "vmlinux.h"

// clang-format off
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <string.h>
// clang-format on

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __type(key, __u32);
  __type(value, __u64);
  __uint(max_entries, 1);
} pkt_count SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
  __uint(max_entries, 128);
  __uint(key_size, sizeof(__u32));
  __uint(value_size, sizeof(__u32));
} log_entries SEC(".maps");

static __always_inline void increment_counter() {
  __u32 key = 0;
  __u64 *count = bpf_map_lookup_elem(&pkt_count, &key);
  if (count) __sync_fetch_and_add(count, 1);
}

#define IPv6HDR_LEN sizeof(struct ipv6hdr)
#define ICMPv6_CSUM_OFF offsetof(struct icmp6hdr, icmp6_cksum)

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

  ulogf("src: %pI6, dst: %pI6", (u64)&ip6h->saddr, (u64)&ip6h->daddr);

  // clang-format off
  static const struct in6_addr to_find = {
      .in6_u.u6_addr8 = {0xfc, 0x00, 0x00, 0x0a, 0x00, 0xff, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
  };
  // clang-format on

  // clang-format off
  static const struct in6_addr to_repr = {
      .in6_u.u6_addr8 = {0xfc, 0x00, 0x00, 0x0a, 0x00, 0x21, 0x00, 0x00, 0, 0, 0, 0, 0, 0, 0, 0}
  };
  // clang-format on

  const struct in6_addr old_dst = ip6h->daddr;

  if (memcmp(&ip6h->daddr, &to_find, 16) == 0) {
    static const int dst_off = offsetof(struct ipv6hdr, daddr);
    if (bpf_skb_store_bytes(skb, dst_off, &to_repr, 16, 0) < 0) {
      bpf_printk("store bytes failed");
      return BPF_DROP;
    }

    increment_counter();

    // Reload data pointers after modifying the packet
    data = (void *)(long)skb->data;
    data_end = (void *)(long)skb->data_end;
    ip6h = data;

    // Re-validate the IPv6 header pointer
    if (data + sizeof(*ip6h) > data_end) {
      bpf_printk("packet truncated after modification");
      return BPF_DROP;
    }

    const struct in6_addr new_dst = ip6h->daddr;

    if (ip6h->nexthdr == IPPROTO_ICMPV6) {
      const int off = IPv6HDR_LEN + ICMPv6_CSUM_OFF;

      for (int i = 0; i < 4; i++) {
        u32 from = old_dst.in6_u.u6_addr32[i];
        u32 to = new_dst.in6_u.u6_addr32[i];

        if (bpf_l4_csum_replace(skb, off, from, to, BPF_F_PSEUDO_HDR | 2) < 0) {
          bpf_printk("l4 csum replace failed");
          return BPF_DROP;
        }

        data = (void *)(long)skb->data;
        data_end = (void *)(long)skb->data_end;
        ip6h = data;

        if (data + sizeof(*ip6h) > data_end) {
          bpf_printk("packet truncated after modification");
          return BPF_DROP;
        }
      }
    }
  }

  return BPF_LWT_REROUTE;
}

char _license[] SEC("license") = "GPL";
