// clang-format off
#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
// clang-format on

/* from linux/pkt_cls.h
 * which I couldn't import directly because it's re-defining stuff
 * already in vmlinux.h
 * */
#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7

char LICENSE[] SEC("license") = "GPL";
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024);
} events_buf SEC(".maps");

SEC("fexit/inet_bind")
int BPF_PROG(inet_bind_exit, struct socket *sock, struct sockaddr *uaddr,
             int addr_len, int ret) {
  if (ret != 0)
    return 0; // bind failed, ignore

  struct sock *sk = BPF_CORE_READ(sock, sk);
  struct net *net = BPF_CORE_READ(sk, __sk_common.skc_net.net);

  struct bind_event event = {
      .pid = (u32)(bpf_get_current_pid_tgid() >> 32),
      .port = bpf_ntohs(((struct sockaddr_in *)uaddr)->sin_port),
      .is_release = false,
      .cookie = bpf_get_socket_cookie(sock->sk),
      .ns_cookie = BPF_CORE_READ(net, net_cookie),
  };
  bpf_ringbuf_output(&events_buf, &event, sizeof(event), 0);
  return 0;
}

SEC("kprobe/inet_csk_listen_stop")
int BPF_KPROBE(inet_listen_stop, struct sock *sock) {
  struct net *net = BPF_CORE_READ(sock, __sk_common.skc_net.net);

  struct bind_event event = {
      .pid = (u32)(bpf_get_current_pid_tgid() >> 32),
      .is_release = true,
      .port = BPF_CORE_READ(sock, __sk_common.skc_num),
      .cookie = BPF_CORE_READ(sock, __sk_common.skc_cookie).counter,
      .ns_cookie = BPF_CORE_READ(net, net_cookie),
  };
  bpf_ringbuf_output(&events_buf, &event, sizeof(event), 0);
  return 0;
}

static __always_inline struct tcphdr *parse_tcp(struct __sk_buff *skb) {
  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  struct ethhdr *eth = data;
  if ((void *)(eth + 1) > data_end)
    return NULL;

  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return NULL;
  if (iph->protocol != IPPROTO_TCP)
    return NULL;

  struct tcphdr *tcp = (void *)iph + iph->ihl * 4;
  if ((void *)(tcp + 1) > data_end)
    return NULL;

  return tcp;
}

/*
 * A BPF_PROG_TYPE_SCHED_ACT program.
 *
 * This program will not be loaded by "jolt" directly, instead, it will
 * be loaded via "tc".
 */
SEC("action/dyn_delay")
int tc_dyn_delay(struct __sk_buff *skb) {
  struct tcphdr *tcp = parse_tcp(skb);
  if (tcp == NULL)
    return TC_ACT_UNSPEC;

  __u16 sport = bpf_ntohs(tcp->source);
  __u16 dport = bpf_ntohs(tcp->dest);

  // TODO: lookup a hashmap.
  if (sport == 4242)
    return TC_ACT_OK;

  return TC_ACT_UNSPEC;
}
