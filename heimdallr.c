// +build ignore

#include "common.h"

#include "bpf_helpers.h"
#include "bpf_tracing.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct event {
	u32 pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
} events SEC(".maps");

// Force emitting struct event into the ELF.
const struct event *unused __attribute__((unused));

SEC("uprobe/callback")
int uprobe_callback(struct pt_regs *ctx) {
	struct event event;
	event.pid = bpf_get_current_pid_tgid();
	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &event, sizeof(event));
	return 0;
}
