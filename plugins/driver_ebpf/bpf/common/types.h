// SPDX-License-Identifier: GPL-2.0
// Elkeid eBPF Types - Simplified from Tracee
// Only includes types needed for Elkeid events

#ifndef __ELKEID_TYPES_H__
#define __ELKEID_TYPES_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>

// ========== Constants ==========

#define TASK_COMM_LEN      16
#define MAX_PATH_LEN       256
#define MAX_ARGS_LEN       256
#define MAX_STRING_SIZE    4096
#define MAX_PERCPU_BUFSIZE 8192
#define MAX_BIN_PATH_SIZE  256

// Address families
#define AF_INET  2
#define AF_INET6 10

// File types (from stat.h)
#define S_IFMT   0170000
#define S_IFSOCK 0140000
#define S_IFLNK  0120000
#define S_IFREG  0100000
#define S_IFBLK  0060000
#define S_IFDIR  0040000
#define S_IFCHR  0020000
#define S_IFIFO  0010000

// ========== Elkeid Event IDs ==========
// Matching LKM schema.rs

enum elkeid_event_id {
    ELKEID_EVENT_OPEN            = 2,
    ELKEID_EVENT_MPROTECT        = 10,
    ELKEID_EVENT_CONNECT         = 42,
    ELKEID_EVENT_ACCEPT          = 43,
    ELKEID_EVENT_BIND            = 49,
    ELKEID_EVENT_EXECVE          = 59,
    ELKEID_EVENT_EXIT            = 60,
    ELKEID_EVENT_KILL            = 62,
    ELKEID_EVENT_RENAME          = 82,
    ELKEID_EVENT_LINK            = 86,
    ELKEID_EVENT_PTRACE          = 101,
    ELKEID_EVENT_PRCTL           = 112,
    ELKEID_EVENT_SETSID          = 157,
    ELKEID_EVENT_MOUNT           = 165,
    ELKEID_EVENT_KILL_TKILL      = 200,
    ELKEID_EVENT_EXIT_GROUP      = 231,
    ELKEID_EVENT_MEMFD_CREATE    = 356,
    ELKEID_EVENT_DNS             = 601,
    ELKEID_EVENT_CREATE_FILE     = 602,
    ELKEID_EVENT_MODULE_LOAD     = 603,
    ELKEID_EVENT_UPDATE_CRED     = 604,
    ELKEID_EVENT_RMDIR           = 605,
    ELKEID_EVENT_UNLINK          = 606,
    ELKEID_EVENT_USERMODEHELPER  = 607,
    ELKEID_EVENT_WRITE           = 608,
    ELKEID_EVENT_CHMOD           = 612,
};

// ========== Task Context ==========

typedef struct task_context {
    u64 start_time;           // task's start time (monotonic)
    u32 pid;                  // PID (userspace term)
    u32 tid;                  // TID (userspace term)
    u32 ppid;                 // Parent PID
    u32 uid;                  // Effective UID
    u32 gid;                  // Effective GID
    u32 pgid;                 // Process group ID
    u32 sid;                  // Session ID
    u32 mnt_id;               // Mount namespace ID
    u32 pid_ns;               // PID namespace inum
    char comm[TASK_COMM_LEN]; // Process name
} task_context_t;

// ========== Event Structures ==========
// All structs use __attribute__((packed)) to guarantee C/Go layout match.

// Base event header (60 bytes packed)
typedef struct __attribute__((packed)) event_header {
    u64 timestamp;            // Event timestamp (ns)
    u32 event_id;             // Elkeid event ID
    u32 pid;
    u32 tid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 pgid;
    u32 sid;
    u32 pid_ns;
    char comm[TASK_COMM_LEN];
} event_header_t;

// Execve event (ID 59)
typedef struct __attribute__((packed)) execve_event {
    event_header_t header;
    char exe[MAX_PATH_LEN];
    char cwd[MAX_PATH_LEN];
    char stdin_path[MAX_PATH_LEN];
    char stdout_path[MAX_PATH_LEN];
    char tty[32];
    char argv[MAX_ARGS_LEN];
    int argc;
    int ret;
    u32 stdin_type;
    u32 stdout_type;
} execve_event_t;

// Exit event (ID 60/231)
typedef struct __attribute__((packed)) exit_event {
    event_header_t header;
    char exe[MAX_PATH_LEN];
    int exit_code;
} exit_event_t;

// Network event base (connect/accept/bind)
typedef struct __attribute__((packed)) net_event {
    event_header_t header;
    char exe[MAX_PATH_LEN];
    u16 sa_family;
    u16 sport;
    u16 dport;
    u8 sip[16];
    u8 dip[16];
    int ret;
} net_event_t;

// File event (open/write/rename/unlink)
typedef struct __attribute__((packed)) file_event {
    event_header_t header;
    char exe[MAX_PATH_LEN];
    char file_path[MAX_PATH_LEN];
    char new_path[MAX_PATH_LEN];
    int flags;
    int mode;
    int ret;
} file_event_t;

// Module load event (ID 603)
typedef struct __attribute__((packed)) module_event {
    event_header_t header;
    char exe[MAX_PATH_LEN];
    char module_name[64];
    char ko_file[MAX_PATH_LEN];
} module_event_t;

// Credential change event (ID 604)
typedef struct __attribute__((packed)) cred_event {
    event_header_t header;
    char exe[MAX_PATH_LEN];
    u32 old_uid;
    u32 new_uid;
    u32 old_euid;
    u32 new_euid;
} cred_event_t;

// DNS query event (ID 601)
typedef struct __attribute__((packed)) dns_event {
    event_header_t header;
    char exe[MAX_PATH_LEN];
    char query[256];
    u16 sa_family;
    u16 sport;
    u16 dport;
    u8 sip[16];
    u8 dip[16];
    u16 opcode;
    u16 rcode;
} dns_event_t;

// ========== Buffer Types ==========

#define MAX_BUFFERS 3

enum buf_idx {
    BUF_IDX_SUBMIT = 0,
    BUF_IDX_STRING = 1,
    BUF_IDX_TMP    = 2,
};

typedef struct simple_buf {
    u8 data[MAX_PERCPU_BUFSIZE];
} buf_t;

// ========== Config ==========

typedef struct elkeid_config {
    u32 root_pid_ns;          // Root PID namespace inum
    u32 options;              // Feature flags
} elkeid_config_t;

// Config options
#define OPT_CAPTURE_EXEC_ENV  (1 << 0)
#define OPT_CAPTURE_FILE_HASH (1 << 1)

#endif /* __ELKEID_TYPES_H__ */
