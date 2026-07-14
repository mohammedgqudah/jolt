#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "GPL";

SEC("lsm/file_mprotect")
int BPF_PROG(block_wx_mprotect, struct vm_area_struct *vma,
             unsigned long reqprot, unsigned long prot, int ret) {
  if (ret != 0)
    return ret;

  struct mm_struct *mm = vma->vm_mm;
  if (!mm)
    return 0;

  bool is_heap = vma->vm_start >= mm->start_brk && vma->vm_end <= mm->brk;

  if (is_heap && (prot & 0x4 /* PROT_EXEC */))
    return -1;

  return 0;
}

