// SPDX-License-Identifier: GPL-2.0
// Elkeid eBPF Maps - Simplified from Tracee
// Only includes maps needed for Elkeid events

#ifndef __ELKEID_MAPS_H__
#define __ELKEID_MAPS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include "types.h"

// ========== Perf Event Maps ==========

// Main event output buffer
struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

// ========== Configuration Maps ==========

// Global configuration
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, elkeid_config_t);
} config_map SEC(".maps");

// ========== Process Info Maps ==========

// Process info cache (pid -> proc_info)
typedef struct proc_info {
    u64 start_time;
    u32 ppid;
    u32 uid;
    u32 gid;
    char exe[MAX_PATH_LEN];
    char comm[TASK_COMM_LEN];
} proc_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, proc_info_t);
} proc_info_map SEC(".maps");

// Task info for tracking between entry and exit
typedef struct task_info {
    u64 syscall_ts;
    u32 syscall_id;
    u64 args[6];
} task_info_t;

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, task_info_t);
} task_info_map SEC(".maps");

// ========== Per-CPU Buffers ==========

// Temporary buffers for building events
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, MAX_BUFFERS);
    __type(key, u32);
    __type(value, buf_t);
} bufs SEC(".maps");

// ========== Args Map (for kretprobe) ==========

typedef struct args {
    u64 args[6];
} args_t;

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, args_t);
} args_map SEC(".maps");

// ========== Filter Maps ==========

// Event enable map: event_id -> enabled (1=on, 0=off)
// If event_id not in map, default is ON (allow-all when map is empty)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, u32);
    __type(value, u8);
} event_filter SEC(".maps");

// PID allowlist: skip event if pid IS in this map (whitelist = don't monitor)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, u8);
} pid_filter SEC(".maps");

// Comm allowlist: skip event if comm IS in this map
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, char[TASK_COMM_LEN]);
    __type(value, u8);
} comm_filter SEC(".maps");

// Write path filter: only report vfs_write for paths in this map
#define MAX_FILTER_PATH 64
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 64);
    __type(key, char[MAX_FILTER_PATH]);
    __type(value, u8);
} write_path_filter SEC(".maps");

// ========== Tail Call Maps ==========

// Program array for tail calls
struct {
    __uint(type, BPF_MAP_TYPE_PROG_ARRAY);
    __uint(max_entries, 32);
    __type(key, u32);
    __type(value, u32);
} prog_array SEC(".maps");

// Tail call indices
enum prog_array_idx {
    PROG_EXECVE_TAIL = 0,
    PROG_OPEN_TAIL   = 1,
    PROG_CONNECT_TAIL = 2,
    // Add more as needed
};

// ========== Helper Macros ==========

// Get per-CPU buffer
static __always_inline buf_t *get_buf(int idx)
{
    return bpf_map_lookup_elem(&bufs, &idx);
}

// Get config
static __always_inline elkeid_config_t *get_config(void)
{
    u32 key = 0;
    return bpf_map_lookup_elem(&config_map, &key);
}

// Get process info
static __always_inline proc_info_t *get_proc_info(u32 pid)
{
    return bpf_map_lookup_elem(&proc_info_map, &pid);
}

// Update process info
static __always_inline int update_proc_info(u32 pid, proc_info_t *info)
{
    return bpf_map_update_elem(&proc_info_map, &pid, info, BPF_ANY);
}

// Delete process info
static __always_inline int delete_proc_info(u32 pid)
{
    return bpf_map_delete_elem(&proc_info_map, &pid);
}

#endif /* __ELKEID_MAPS_H__ */
