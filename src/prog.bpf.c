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

/*
 * Store the client PID from tcp_v4_connect to the accept event.
 */
struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 1024);
  __type(key, u32);
  __type(value, u32);
} connect_pid SEC(".maps");

SEC("fexit/inet_bind")
int BPF_PROG(inet_bind_exit, struct socket *sock, struct sockaddr *uaddr,
             int addr_len, int ret) {
  if (ret != 0)
    return 0; // bind failed, ignore

  struct sock *sk = BPF_CORE_READ(sock, sk);
  struct net *net = BPF_CORE_READ(sk, __sk_common.skc_net.net);

  struct jolt_event event = {
      .pid = (u32)(bpf_get_current_pid_tgid() >> 32),
      .tag = EVENT_BIND,
      .data =
          {
              .socket =
                  {
                      .port =
                          bpf_ntohs(((struct sockaddr_in *)uaddr)->sin_port),
                      .cookie = bpf_get_socket_cookie(sock->sk),
                      .ns_cookie = BPF_CORE_READ(net, net_cookie),
                  },
          },
  };
  bpf_ringbuf_output(&events_buf, &event, sizeof(event), 0);
  return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(inet_csk_accept_exit, struct sock *sk, int flags,
             struct sock *child_sk) {
  if (!child_sk)
    return 0;

  struct net *net = BPF_CORE_READ(sk, __sk_common.skc_net.net);

  __u16 server_port = BPF_CORE_READ(sk, __sk_common.skc_num);
  __u16 client_port =
      bpf_ntohs(BPF_CORE_READ(child_sk, __sk_common.skc_dport));

  /* Look up the client PID that was stored by tcp_v4_connect. */
  u32 map_key = ((u32)client_port << 16) | server_port;
  u32 *client_pid = bpf_map_lookup_elem(&connect_pid, &map_key);

  struct jolt_event event = {
      .pid = (u32)(bpf_get_current_pid_tgid() >> 32),
      .tag = EVENT_ACCEPT,
      .data.accept =
          {
              .listening =
                  {
                      .port = server_port,
                      .cookie =
                          BPF_CORE_READ(sk, __sk_common.skc_cookie).counter,
                      .ns_cookie = BPF_CORE_READ(net, net_cookie),
                  },
              .rport = client_port,
              .client_pid = client_pid ? *client_pid : 0,
          },
  };

  bpf_ringbuf_output(&events_buf, &event, sizeof(event), 0);

  if (client_pid)
    bpf_map_delete_elem(&connect_pid, &map_key);
  return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(tcp_v4_connect_exit, struct sock *sk, struct sockaddr *uaddr,
             int addr_len, int ret) {
  if (ret < 0)
    return 0; 

  __u16 src_port = BPF_CORE_READ(sk, __sk_common.skc_num);
  __u16 dst_port =
      bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

  u64 pid_tgid = bpf_get_current_pid_tgid();
  u32 pid = pid_tgid >> 32;

  // store pid in key(src_port, dst_port) so the accept probe can get client pid
  // TODO: key should be a tuple of (addr, sport, dport, netns)
  u32 key = ((u32)src_port << 16) | dst_port;
  bpf_map_update_elem(&connect_pid, &key, &pid, BPF_ANY);
  return 0;
}

SEC("kprobe/inet_csk_listen_stop")
int BPF_KPROBE(inet_listen_stop, struct sock *sock) {
  struct net *net = BPF_CORE_READ(sock, __sk_common.skc_net.net);

  struct jolt_event event = {
      .pid = (u32)(bpf_get_current_pid_tgid() >> 32),
      .tag = EVENT_RELEASE,
      .data = {
          .socket =
              {
                  .port = BPF_CORE_READ(sock, __sk_common.skc_num),
                  .cookie = BPF_CORE_READ(sock, __sk_common.skc_cookie).counter,
                  .ns_cookie = BPF_CORE_READ(net, net_cookie),
              },
      }};
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
