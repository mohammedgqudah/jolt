#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include "common.h"

char LICENSE[] SEC("license") = "GPL";
struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024);
} events_buf SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1024);
} some_rb SEC(".maps");

const volatile uint32_t target_pid = 0;

SEC("fexit/inet_bind")
int BPF_PROG(inet_bind_exit, struct socket *sock, struct sockaddr *uaddr,
             int addr_len, int ret) {
  if (ret != 0)
    return 0; // bind failed, ignore

  struct bind_event event = {
      .pid = (u32)(bpf_get_current_pid_tgid() >> 32),
      .port = bpf_ntohs(((struct sockaddr_in *)uaddr)->sin_port),
      .is_release = false,
  };
  bpf_ringbuf_output(&events_buf, &event, sizeof(event), 0);
  return 0;
}

SEC("kprobe/inet_csk_listen_stop")
int BPF_KPROBE(inet_listen_stop, struct sock *sock) {
  struct bind_event event = {
      .pid = (u32)(bpf_get_current_pid_tgid() >> 32),
      .is_release = true,
      .port = BPF_CORE_READ(sock, __sk_common.skc_num),
  };
  bpf_ringbuf_output(&events_buf, &event, sizeof(event), 0);
  return 0;
}
