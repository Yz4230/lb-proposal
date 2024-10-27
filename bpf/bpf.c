// go:build ignore

#include "net_shared.h"
#include "vmlinux.h"

// clang-format off
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
// clang-format on

#include "test_update_dst.h"

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

  do_test_data(skb);

  return BPF_LWT_REROUTE;
}

char _license[] SEC("license") = "GPL";
