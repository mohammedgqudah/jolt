#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
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
      .port = ((struct sockaddr_in *)uaddr)->sin_port,
  };
  bpf_ringbuf_output(&events_buf, &event, sizeof(event), 0);
  return 0;
}

