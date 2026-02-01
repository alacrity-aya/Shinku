#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

SEC("tp/syscalls/sys_enter_write")
int handle_write(struct trace_event_raw_sys_enter *ctx) {
  u32 pid = bpf_get_current_pid_tgid() >> 32;
  bpf_printk("PID %d is writing\n", pid);
  return 0;
}

char LICENSE[] SEC("license") = "GPL";
