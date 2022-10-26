// +build ignore

#include <linux/ptrace.h>
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char __license[] SEC("license") = "Dual MIT/GPL";

struct bpf_map_def SEC("maps") args = {
    .type = BPF_MAP_TYPE_ARRAY,
    .key_size = sizeof(__u32),
    .value_size = sizeof(__u8),
    .max_entries = 100,
};

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 24);
} events SEC(".maps");

#pragma pack(1)
struct endInfo {
    __u8 t;
	__u32 rid;
};

#pragma pack(1)
struct goString {
    __u8 t;
	__u32 rid;
    unsigned long len;
    __u8 s[80];
};

#pragma pack(1)
struct goInt {
    __u8 t;
	__u32 rid;
	__u32 i;
};

// Force emitting struct event into the ELF.
const struct endInfo *unused __attribute__((unused));
const struct goString *unused1 __attribute__((unused));
const struct goInt *unused2 __attribute__((unused));

SEC("uprobe/callback")
int uprobe_callback(struct pt_regs *ctx) {

    __u32 rid = bpf_get_prandom_u32();
    struct goString strArg;
    struct goInt intArg;

    strArg.t = 14;
    strArg.rid = rid;
    strArg.len = ctx->rbx;
    // 暂时只能传小于 goString.s 大小的字符串，后续超过长度会分段传输
    bpf_probe_read(&strArg.s, sizeof(strArg.s), (void *)ctx->rax);
    bpf_ringbuf_output(&events, &strArg, sizeof(strArg), 0);

    strArg.len = ctx->rdi;
    bpf_probe_read(&strArg.s, sizeof(strArg.s), (void *)ctx->rcx);
    bpf_ringbuf_output(&events, &strArg, sizeof(strArg), 0);

    strArg.len = ctx->r8;
    bpf_probe_read(&strArg.s, sizeof(strArg.s), (void *)ctx->rsi);
    bpf_ringbuf_output(&events, &strArg, sizeof(strArg), 0);

    strArg.len = ctx->r10;
    bpf_probe_read(&strArg.s, sizeof(strArg.s), (void *)ctx->r9);
    bpf_ringbuf_output(&events, &strArg, sizeof(strArg), 0);

    intArg.t = 1;
    intArg.rid = rid;
    intArg.i = ctx->r11;
    bpf_ringbuf_output(&events, &intArg, sizeof(intArg), 0);

    void* stackAddr = (void*)ctx->rsp;
	bpf_probe_read(&intArg.i, sizeof(intArg.i), stackAddr+8);
    bpf_ringbuf_output(&events, &intArg, sizeof(intArg), 0);

	bpf_probe_read(&intArg.i, sizeof(intArg.i), stackAddr+16);
    bpf_ringbuf_output(&events, &intArg, sizeof(intArg), 0);

    void * strPointer;
    bpf_probe_read(&strPointer, sizeof(strPointer), stackAddr+24);

    bpf_probe_read(&strArg.len, sizeof(strArg.len), stackAddr+32);
    bpf_probe_read(&strArg.s, sizeof(strArg.s), strPointer);
    bpf_ringbuf_output(&events, &strArg, sizeof(strArg), 0);

    // endinfo
    struct endInfo endinfo;
    endinfo.t = 0;
    endinfo.rid = rid;
    bpf_ringbuf_output(&events, &endinfo, sizeof(endinfo), 0);
	return 0;
}
