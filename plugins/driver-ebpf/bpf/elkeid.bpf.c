// SPDX-License-Identifier: GPL-2.0
// Elkeid eBPF Driver - Main BPF Program
// Based on Tracee with Elkeid-specific additions
// 
// This file implements event hooks for:
// - P0: execve, exit, connect
// - P1: accept, bind, open, kill, module_load, update_cred
// - P2: rename, link, mount, write, prctl, dns, etc.

#include "common/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#include "common/types.h"
#include "common/maps.h"
#include "common/helpers.h"

char LICENSE[] SEC("license") = "GPL";

// ========== Path String Helper ==========
// Simplified path resolution (max depth to avoid verifier issues)

#define MAX_PATH_DEPTH 20

statfunc int get_dentry_path(struct dentry *dentry, char *buf, int size)
{
    struct dentry *d = dentry;
    struct dentry *parent;
    int offset = size - 1;
    buf[offset] = '\0';

    #pragma unroll
    for (int i = 0; i < MAX_PATH_DEPTH; i++) {
        parent = BPF_CORE_READ(d, d_parent);
        if (d == parent)
            break;
        
        struct qstr dname = BPF_CORE_READ(d, d_name);
        const unsigned char *name = dname.name;
        unsigned int len = dname.len;
        
        if (len == 0 || offset <= 1)
            break;
        
        // Check length safely
        if (len > 255)
            len = 255;
        if (len >= offset)
            len = offset - 1;
        
        offset -= len;
        bpf_core_read(&buf[offset], len, name);
        
        offset--;
        buf[offset] = '/';
        
        d = parent;
    }

    // Move string to beginning of buffer
    if (offset > 0) {
        int copy_len = size - offset;
        #pragma unroll
        for (int i = 0; i < 256 && i < copy_len; i++) {
            buf[i] = buf[offset + i];
        }
    }

    return 0;
}

statfunc int get_file_path(struct file *file, char *buf, int size)
{
    if (!file) {
        buf[0] = '\0';
        return -1;
    }
    struct dentry *dentry = BPF_CORE_READ(file, f_path.dentry);
    return get_dentry_path(dentry, buf, size);
}

// ========== EXECVE Event (ID 59) ==========
// Hook: sched_process_exec
// Triggered when a process successfully calls execve()

SEC("raw_tracepoint/sched_process_exec")
int elkeid_sched_process_exec(struct bpf_raw_tracepoint_args *ctx)
{
    if (should_filter_event(ELKEID_EVENT_EXECVE))
        return 0;

    struct task_struct *task = (struct task_struct *)ctx->args[0];
    struct linux_binprm *bprm = (struct linux_binprm *)ctx->args[2];
    
    if (!task || !bprm)
        return 0;

    // Get per-CPU buffer for event
    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    execve_event_t *event = (execve_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    // Fill header
    init_event_header(&event->header, ELKEID_EVENT_EXECVE);
    
    // Override some fields from task context
    event->header.pid = BPF_CORE_READ(task, tgid);
    event->header.tid = BPF_CORE_READ(task, pid);
    event->header.ppid = get_task_ppid(task);
    event->header.uid = get_task_uid(task);
    event->header.gid = get_task_gid(task);
    event->header.pgid = get_task_pgid(task);
    event->header.sid = get_task_sid(task);        // Elkeid specific: session ID
    event->header.pid_ns = get_task_pid_ns_id(task);
    bpf_core_read_str(&event->header.comm, sizeof(event->header.comm), 
                      BPF_CORE_READ(task, comm));

    // Get executable path from bprm->file
    struct file *exe_file = BPF_CORE_READ(bprm, file);
    if (exe_file) {
        get_file_path(exe_file, event->exe, sizeof(event->exe));
    }

    // Get current working directory
    struct fs_struct *fs = BPF_CORE_READ(task, fs);
    if (fs) {
        struct path pwd = BPF_CORE_READ(fs, pwd);
        struct dentry *pwd_dentry = pwd.dentry;
        if (pwd_dentry) {
            get_dentry_path(pwd_dentry, event->cwd, sizeof(event->cwd));
        }
    }

    // Get stdin (fd=0)
    struct file *stdin_file = get_struct_file_from_fd(0);
    if (stdin_file) {
        event->stdin_type = get_inode_mode_from_file(stdin_file) & S_IFMT;
        get_file_path(stdin_file, event->stdin_path, sizeof(event->stdin_path));
    }

    // Elkeid specific: Get stdout (fd=1)
    struct file *stdout_file = get_struct_file_from_fd(1);
    if (stdout_file) {
        event->stdout_type = get_inode_mode_from_file(stdout_file) & S_IFMT;
        get_file_path(stdout_file, event->stdout_path, sizeof(event->stdout_path));
    }

    // Get TTY
    get_tty_name(task, event->tty, sizeof(event->tty));

    // Get arguments (simplified - just argc for now, full args in Go layer)
    struct mm_struct *mm = BPF_CORE_READ(task, mm);
    if (mm) {
        unsigned long arg_start = BPF_CORE_READ(mm, arg_start);
        unsigned long arg_end = BPF_CORE_READ(mm, arg_end);
        
        // Read first part of arguments
        int argv_len = arg_end - arg_start;
        if (argv_len > 0) {
            if (argv_len > sizeof(event->argv) - 1)
                argv_len = sizeof(event->argv) - 1;
            bpf_probe_read_user(&event->argv, argv_len, (void *)arg_start);
        }
        
        event->argc = BPF_CORE_READ(bprm, argc);
    }

    // Submit event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    // Update proc_info cache
    proc_info_t proc_info = {};
    proc_info.start_time = get_task_start_time(task);
    proc_info.ppid = event->header.ppid;
    proc_info.uid = event->header.uid;
    proc_info.gid = event->header.gid;
    __builtin_memcpy(proc_info.comm, event->header.comm, TASK_COMM_LEN);
    bpf_probe_read_kernel_str(proc_info.exe, sizeof(proc_info.exe), event->exe);
    update_proc_info(event->header.pid, &proc_info);

    return 0;
}

// ========== EXIT Event (ID 60/231) ==========
// Hook: sched_process_exit
// Triggered when a process/thread exits

SEC("raw_tracepoint/sched_process_exit")
int elkeid_sched_process_exit(struct bpf_raw_tracepoint_args *ctx)
{
    if (should_filter_event(ELKEID_EVENT_EXIT))
        return 0;

    struct task_struct *task = (struct task_struct *)ctx->args[0];
    if (!task)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    exit_event_t *event = (exit_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    // Determine if this is exit (60) or exit_group (231)
    // exit_group is when the whole process (thread group) exits
    u32 pid = BPF_CORE_READ(task, pid);
    u32 tgid = BPF_CORE_READ(task, tgid);
    
    // Check if thread group leader (main thread)
    bool is_leader = (pid == tgid);
    
    // Check if whole group is dead
    struct signal_struct *sig = BPF_CORE_READ(task, signal);
    int live_count = 0;
    if (sig) {
        atomic_t live = BPF_CORE_READ(sig, live);
        live_count = live.counter;
    }
    
    // Set event ID
    if (is_leader || live_count == 0) {
        init_event_header(&event->header, ELKEID_EVENT_EXIT_GROUP);
    } else {
        init_event_header(&event->header, ELKEID_EVENT_EXIT);
    }

    // Fill task info
    event->header.pid = tgid;
    event->header.tid = pid;
    event->header.ppid = get_task_ppid(task);
    event->header.uid = get_task_uid(task);
    event->header.gid = get_task_gid(task);
    bpf_core_read_str(&event->header.comm, sizeof(event->header.comm),
                      BPF_CORE_READ(task, comm));

    // Get exit code
    int exit_code = get_task_exit_code(task);
    event->exit_code = exit_code >> 8;  // Extract actual exit code

    // Try to get exe from proc_info cache
    proc_info_t *pinfo = get_proc_info(tgid);
    if (pinfo) {
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));
    }

    // Submit event
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    // Clean up proc_info if whole process exits
    if (is_leader || live_count == 0) {
        delete_proc_info(tgid);
    }

    return 0;
}

// ========== CONNECT Event (ID 42) ==========
// Hook: security_socket_connect (kprobe + kretprobe)
// kprobe saves address info, kretprobe captures return value and sends event

SEC("kprobe/security_socket_connect")
int BPF_KPROBE(elkeid_security_socket_connect,
               struct socket *sock,
               struct sockaddr *address,
               int addrlen)
{
    if (should_filter_event(ELKEID_EVENT_CONNECT))
        return 0;
    if (!sock || !address)
        return 0;

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);

    if (family != AF_INET && family != AF_INET6)
        return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    args_t args = {};
    args.args[0] = family;

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
        u16 dport = 0;
        bpf_probe_read_kernel(&dport, sizeof(dport), &addr4->sin_port);
        args.args[1] = __builtin_bswap16(dport);
        bpf_probe_read_kernel(&args.args[2], 4, &addr4->sin_addr);
    } else {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
        u16 dport = 0;
        bpf_probe_read_kernel(&dport, sizeof(dport), &addr6->sin6_port);
        args.args[1] = __builtin_bswap16(dport);
        bpf_probe_read_kernel(&args.args[2], 8, &addr6->sin6_addr);
        bpf_probe_read_kernel(&args.args[3], 8, ((char *)&addr6->sin6_addr) + 8);
    }

    bpf_map_update_elem(&args_map, &pid_tgid, &args, BPF_ANY);
    return 0;
}

SEC("kretprobe/security_socket_connect")
int BPF_KRETPROBE(elkeid_security_socket_connect_ret, int ret)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    args_t *args = bpf_map_lookup_elem(&args_map, &pid_tgid);
    if (!args)
        return 0;

    u16 family = (u16)args->args[0];
    u16 dport = (u16)args->args[1];
    u64 dip_lo = args->args[2];
    u64 dip_hi = args->args[3];

    bpf_map_delete_elem(&args_map, &pid_tgid);

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    net_event_t *event = (net_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_CONNECT);

    event->sa_family = family;
    event->dport = dport;
    event->ret = ret;

    if (family == AF_INET) {
        __builtin_memcpy(event->dip, &dip_lo, 4);
    } else if (family == AF_INET6) {
        __builtin_memcpy(event->dip, &dip_lo, 8);
        __builtin_memcpy(event->dip + 8, &dip_hi, 8);
    }

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// ========== Module Load Event (ID 603) ==========
// Hook: do_init_module
// Triggered when a kernel module is loaded

SEC("kprobe/do_init_module")
int BPF_KPROBE(elkeid_do_init_module, struct module *mod)
{
    if (should_filter_event(ELKEID_EVENT_MODULE_LOAD))
        return 0;
    if (!mod)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    module_event_t *event = (module_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_MODULE_LOAD);

    // Get module name
    bpf_core_read_str(&event->module_name, sizeof(event->module_name), mod->name);

    // Get caller info
    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo) {
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Credential Change Event (ID 604) ==========
// Hook: commit_creds
// Triggered when a process changes credentials

SEC("kprobe/commit_creds")
int BPF_KPROBE(elkeid_commit_creds, struct cred *new_cred)
{
    if (should_filter_event(ELKEID_EVENT_UPDATE_CRED))
        return 0;
    if (!new_cred)
        return 0;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *old_cred = get_task_real_cred(task);
    if (!old_cred)
        return 0;

    // Get old and new UIDs
    u32 old_uid = BPF_CORE_READ(old_cred, uid.val);
    u32 new_uid = BPF_CORE_READ(new_cred, uid.val);
    u32 old_euid = BPF_CORE_READ(old_cred, euid.val);
    u32 new_euid = BPF_CORE_READ(new_cred, euid.val);

    // Skip if no actual change
    if (old_uid == new_uid && old_euid == new_euid)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    cred_event_t *event = (cred_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_UPDATE_CRED);

    event->old_uid = old_uid;
    event->new_uid = new_uid;
    event->old_euid = old_euid;
    event->new_euid = new_euid;

    // Get executable path
    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo) {
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== File Open Event (ID 2) ==========
// Hook: security_file_open
// Triggered when a file is opened

SEC("kprobe/security_file_open")
int BPF_KPROBE(elkeid_security_file_open, struct file *file)
{
    if (should_filter_event(ELKEID_EVENT_OPEN))
        return 0;
    if (!file)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_OPEN);

    // Get file path
    get_file_path(file, event->file_path, sizeof(event->file_path));

    // Get flags and mode
    event->flags = BPF_CORE_READ(file, f_flags);
    event->mode = BPF_CORE_READ(file, f_mode);

    // Get executable path
    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo) {
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== File Unlink Event (ID 606) ==========
// Hook: security_inode_unlink

SEC("kprobe/security_inode_unlink")
int BPF_KPROBE(elkeid_security_inode_unlink, 
               struct inode *dir, 
               struct dentry *dentry)
{
    if (should_filter_event(ELKEID_EVENT_UNLINK))
        return 0;
    if (!dentry)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_UNLINK);

    // Get file path
    get_dentry_path(dentry, event->file_path, sizeof(event->file_path));

    // Get executable path
    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo) {
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Rename Event (ID 82) ==========
// Hook: security_inode_rename

SEC("kprobe/security_inode_rename")
int BPF_KPROBE(elkeid_security_inode_rename,
               struct inode *old_dir,
               struct dentry *old_dentry,
               struct inode *new_dir,
               struct dentry *new_dentry)
{
    if (should_filter_event(ELKEID_EVENT_RENAME))
        return 0;
    if (!old_dentry || !new_dentry)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_RENAME);

    // Get old and new paths
    get_dentry_path(old_dentry, event->file_path, sizeof(event->file_path));
    get_dentry_path(new_dentry, event->new_path, sizeof(event->new_path));

    // Get executable path
    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo) {
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));
    }

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Usermodehelper Event (ID 607) ==========
// Hook: call_usermodehelper

SEC("kprobe/call_usermodehelper")
int BPF_KPROBE(elkeid_call_usermodehelper,
               const char *path,
               char **argv,
               char **envp,
               int wait)
{
    if (should_filter_event(ELKEID_EVENT_USERMODEHELPER))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_USERMODEHELPER);

    if (path) {
        bpf_probe_read_kernel_str(event->file_path, sizeof(event->file_path), path);
    }

    // Capture first argv element into new_path field
    if (argv) {
        const char *arg0 = NULL;
        bpf_probe_read_kernel(&arg0, sizeof(arg0), &argv[0]);
        if (arg0)
            bpf_probe_read_kernel_str(event->new_path, sizeof(event->new_path), arg0);
    }

    event->flags = wait;

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Accept Event (ID 43) ==========
// Hook: inet_csk_accept kretprobe
// Returns the newly accepted struct sock * with full connection info

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(elkeid_inet_csk_accept_ret, struct sock *newsk)
{
    if (should_filter_event(ELKEID_EVENT_ACCEPT))
        return 0;
    if (!newsk)
        return 0;

    u16 family = BPF_CORE_READ(newsk, __sk_common.skc_family);
    if (family != AF_INET && family != AF_INET6)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    net_event_t *event = (net_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_ACCEPT);
    event->sa_family = family;
    event->ret = 0;

    if (family == AF_INET) {
        event->sport = BPF_CORE_READ(newsk, __sk_common.skc_num);
        event->dport = __builtin_bswap16(BPF_CORE_READ(newsk, __sk_common.skc_dport));
        u32 saddr = BPF_CORE_READ(newsk, __sk_common.skc_rcv_saddr);
        u32 daddr = BPF_CORE_READ(newsk, __sk_common.skc_daddr);
        __builtin_memcpy(event->sip, &saddr, 4);
        __builtin_memcpy(event->dip, &daddr, 4);
    } else {
        event->sport = BPF_CORE_READ(newsk, __sk_common.skc_num);
        event->dport = __builtin_bswap16(BPF_CORE_READ(newsk, __sk_common.skc_dport));
        bpf_core_read(event->sip, 16, &newsk->__sk_common.skc_v6_rcv_saddr);
        bpf_core_read(event->dip, 16, &newsk->__sk_common.skc_v6_daddr);
    }

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// ========== Create File Event (ID 602) ==========
// Hook: security_inode_create
// Triggered when a new file is created

SEC("kprobe/security_inode_create")
int BPF_KPROBE(elkeid_security_inode_create,
               struct inode *dir,
               struct dentry *dentry,
               umode_t mode)
{
    if (should_filter_event(ELKEID_EVENT_CREATE_FILE))
        return 0;
    if (!dentry)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_CREATE_FILE);

    get_dentry_path(dentry, event->file_path, sizeof(event->file_path));
    event->mode = (int)mode;

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// ========== Bind Event (ID 49) ==========
// Hook: security_socket_bind

SEC("kprobe/security_socket_bind")
int BPF_KPROBE(elkeid_security_socket_bind,
               struct socket *sock,
               struct sockaddr *address,
               int addrlen)
{
    if (should_filter_event(ELKEID_EVENT_BIND))
        return 0;
    if (!sock || !address)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    net_event_t *event = (net_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_BIND);

    u16 family = 0;
    bpf_probe_read_kernel(&family, sizeof(family), &address->sa_family);
    event->sa_family = family;

    if (family == AF_INET) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)address;
        bpf_probe_read_kernel(&event->sport, sizeof(event->sport), &addr4->sin_port);
        event->sport = __builtin_bswap16(event->sport);
        bpf_probe_read_kernel(&event->sip, 4, &addr4->sin_addr);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)address;
        bpf_probe_read_kernel(&event->sport, sizeof(event->sport), &addr6->sin6_port);
        event->sport = __builtin_bswap16(event->sport);
        bpf_probe_read_kernel(&event->sip, 16, &addr6->sin6_addr);
    } else {
        return 0;
    }

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Kill Event (ID 62) ==========
// Tracepoint: syscalls/sys_enter_kill

SEC("tracepoint/syscalls/sys_enter_kill")
int tracepoint_sys_enter_kill(struct trace_event_raw_sys_enter *ctx)
{
    if (should_filter_event(ELKEID_EVENT_KILL))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_KILL);

    // args[0] = target pid, args[1] = signal
    int target_pid = (int)ctx->args[0];
    int sig = (int)ctx->args[1];
    
    // Store in flags and mode fields
    event->flags = target_pid;
    event->mode = sig;

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Tkill Event (ID 200) ==========
// Tracepoint: syscalls/sys_enter_tkill

SEC("tracepoint/syscalls/sys_enter_tkill")
int tracepoint_sys_enter_tkill(struct trace_event_raw_sys_enter *ctx)
{
    if (should_filter_event(ELKEID_EVENT_KILL_TKILL))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_KILL_TKILL);

    int target_tid = (int)ctx->args[0];
    int sig = (int)ctx->args[1];
    
    event->flags = target_tid;
    event->mode = sig;

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Ptrace Event (ID 101) ==========
// Tracepoint: syscalls/sys_enter_ptrace

SEC("tracepoint/syscalls/sys_enter_ptrace")
int tracepoint_sys_enter_ptrace(struct trace_event_raw_sys_enter *ctx)
{
    if (should_filter_event(ELKEID_EVENT_PTRACE))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_PTRACE);

    // args[0] = request, args[1] = pid
    long request = (long)ctx->args[0];
    long target_pid = (long)ctx->args[1];

    event->flags = (int)request;
    event->mode = (int)target_pid;

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Prctl Event (ID 112) ==========
// Tracepoint: syscalls/sys_enter_prctl

SEC("tracepoint/syscalls/sys_enter_prctl")
int tracepoint_sys_enter_prctl(struct trace_event_raw_sys_enter *ctx)
{
    if (should_filter_event(ELKEID_EVENT_PRCTL))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_PRCTL);

    // args[0] = option, args[1..4] = arg2..arg5
    int option = (int)ctx->args[0];
    event->flags = option;

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Link/Symlink Event (ID 86) ==========
// Hook: security_inode_symlink

SEC("kprobe/security_inode_symlink")
int BPF_KPROBE(elkeid_security_inode_symlink,
               struct inode *dir,
               struct dentry *dentry,
               const char *old_name)
{
    if (should_filter_event(ELKEID_EVENT_LINK))
        return 0;
    if (!dentry)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_LINK);

    // Get symlink path (new name)
    get_dentry_path(dentry, event->file_path, sizeof(event->file_path));

    // Get target (old name)
    if (old_name) {
        bpf_probe_read_kernel_str(event->new_path, sizeof(event->new_path), old_name);
    }

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Mount Event (ID 165) ==========
// Hook: security_sb_mount

SEC("kprobe/security_sb_mount")
int BPF_KPROBE(elkeid_security_sb_mount,
               const char *dev_name,
               const struct path *path,
               const char *type,
               unsigned long flags,
               void *data)
{
    if (should_filter_event(ELKEID_EVENT_MOUNT))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_MOUNT);

    // file_path = dev_name
    if (dev_name) {
        bpf_probe_read_kernel_str(event->file_path, sizeof(event->file_path), dev_name);
    }

    // new_path = mount point
    if (path) {
        struct dentry *dentry = BPF_CORE_READ(path, dentry);
        if (dentry) {
            get_dentry_path(dentry, event->new_path, sizeof(event->new_path));
        }
    }

    // Store fstype in ret field as a hash; actual string goes via Go /proc/mounts
    // For now capture type string length to signal presence
    event->flags = (int)flags;
    if (type) {
        char fstype_buf[16] = {};
        bpf_probe_read_kernel_str(fstype_buf, sizeof(fstype_buf), type);
        // Pack first 4 chars of fstype into ret for quick identification
        event->ret = *(int *)fstype_buf;
    }

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Memfd Create Event (ID 356) ==========
// Tracepoint: syscalls/sys_enter_memfd_create

SEC("tracepoint/syscalls/sys_enter_memfd_create")
int tracepoint_sys_enter_memfd_create(struct trace_event_raw_sys_enter *ctx)
{
    if (should_filter_event(ELKEID_EVENT_MEMFD_CREATE))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_MEMFD_CREATE);

    // args[0] = name, args[1] = flags
    const char *name = (const char *)ctx->args[0];
    unsigned int flags = (unsigned int)ctx->args[1];

    if (name) {
        bpf_probe_read_user_str(event->file_path, sizeof(event->file_path), name);
    }
    event->flags = flags;

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Mprotect Event (ID 10) ==========
// Hook: security_file_mprotect

SEC("kprobe/security_file_mprotect")
int BPF_KPROBE(elkeid_security_file_mprotect,
               struct vm_area_struct *vma,
               unsigned long reqprot,
               unsigned long prot)
{
    if (should_filter_event(ELKEID_EVENT_MPROTECT))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_MPROTECT);

    // Get VMA info
    if (vma) {
        unsigned long vm_start = BPF_CORE_READ(vma, vm_start);
        unsigned long vm_end = BPF_CORE_READ(vma, vm_end);
        
        // Store address range info
        event->flags = (int)prot;
        event->mode = (int)reqprot;

        // Get file path if backed by file
        struct file *vm_file = BPF_CORE_READ(vma, vm_file);
        if (vm_file) {
            get_file_path(vm_file, event->file_path, sizeof(event->file_path));
        }
    }

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Setsid Event (ID 157) ==========
// Hook: syscalls/sys_enter_setsid

SEC("tracepoint/syscalls/sys_enter_setsid")
int tracepoint_sys_enter_setsid(struct trace_event_raw_sys_enter *ctx)
{
    if (should_filter_event(ELKEID_EVENT_SETSID))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_SETSID);

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Rmdir Event (ID 605) ==========
// Hook: security_path_rmdir

SEC("kprobe/security_path_rmdir")
int BPF_KPROBE(elkeid_security_path_rmdir,
               const struct path *dir,
               struct dentry *dentry)
{
    if (should_filter_event(ELKEID_EVENT_RMDIR))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_RMDIR);

    // Get directory path
    if (dentry) {
        get_dentry_path(dentry, event->file_path, sizeof(event->file_path));
    }

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Write Event (ID 608) ==========
// Hook: vfs_write (filtered by monitored paths)
// Note: This generates high volume, need filtering in production

SEC("kprobe/vfs_write")
int BPF_KPROBE(elkeid_vfs_write,
               struct file *file,
               const char *buf,
               size_t count,
               loff_t *pos)
{
    if (should_filter_event(ELKEID_EVENT_WRITE))
        return 0;
    if (!file || count < 1)
        return 0;

    // Get file path for filtering
    char path_buf[MAX_PATH_LEN];
    __builtin_memset(path_buf, 0, sizeof(path_buf));
    get_file_path(file, path_buf, sizeof(path_buf));

    // Map-based path prefix filtering.
    // Check several well-known sensitive prefixes via write_path_filter map.
    // If the map is empty, fall back to default /etc prefix check.
    char prefix_key[MAX_FILTER_PATH] = {};

    // Extract first path component (up to MAX_FILTER_PATH)
    #pragma unroll
    for (int i = 0; i < MAX_FILTER_PATH - 1 && i < MAX_PATH_LEN; i++) {
        prefix_key[i] = path_buf[i];
        if (path_buf[i] == '\0')
            break;
    }

    u8 *allowed = bpf_map_lookup_elem(&write_path_filter, prefix_key);
    if (!allowed) {
        // Fallback: only monitor /etc/, /root/, /var/spool/cron
        if (path_buf[0] != '/')
            return 0;
        bool match = false;
        if (path_buf[1] == 'e' && path_buf[2] == 't' && path_buf[3] == 'c' && path_buf[4] == '/')
            match = true;
        if (path_buf[1] == 'r' && path_buf[2] == 'o' && path_buf[3] == 'o' && path_buf[4] == 't')
            match = true;
        if (!match)
            return 0;
    }

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_WRITE);

    __builtin_memcpy(event->file_path, path_buf, sizeof(event->file_path));
    event->flags = (int)count;  // Store write size in flags

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== DNS Event (ID 601) ==========
// Note: DNS monitoring via udp_sendmsg to capture outgoing DNS queries
// Full DNS parsing would require cgroup_skb or socket filter

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(elkeid_udp_sendmsg,
               struct sock *sk,
               struct msghdr *msg,
               size_t len)
{
    if (should_filter_event(ELKEID_EVENT_DNS))
        return 0;

    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    dport = __builtin_bswap16(dport);

    if (dport != 53)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    dns_event_t *event = (dns_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_DNS);

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    event->sa_family = family;
    event->dport = dport;

    if (family == AF_INET) {
        u32 saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        u32 daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        __builtin_memcpy(event->sip, &saddr, 4);
        __builtin_memcpy(event->dip, &daddr, 4);
    } else if (family == AF_INET6) {
        struct in6_addr saddr = BPF_CORE_READ(sk, __sk_common.skc_v6_rcv_saddr);
        struct in6_addr daddr = BPF_CORE_READ(sk, __sk_common.skc_v6_daddr);
        __builtin_memcpy(event->sip, &saddr, 16);
        __builtin_memcpy(event->dip, &daddr, 16);
    }

    // Extract DNS query from msghdr iovec
    // DNS packet: 12-byte header, then query name in label format
    if (msg) {
        const struct iovec *iov = BPF_CORE_READ(msg, msg_iter.__iov);
        if (iov) {
            void *base = BPF_CORE_READ(iov, iov_base);
            unsigned long iov_len = BPF_CORE_READ(iov, iov_len);
            if (base && iov_len > 12) {
                // Copy raw DNS query section (after 12-byte header)
                // into event->query; userspace will parse label format
                unsigned long qlen = iov_len - 12;
                if (qlen > sizeof(event->query) - 1)
                    qlen = sizeof(event->query) - 1;
                // Bound for verifier
                if (qlen > 0 && qlen <= 255)
                    bpf_probe_read_user(event->query, qlen, base + 12);

                // Extract opcode from DNS header bytes 2-3
                u16 dns_flags = 0;
                bpf_probe_read_user(&dns_flags, 2, base + 2);
                dns_flags = __builtin_bswap16(dns_flags);
                event->opcode = (dns_flags >> 11) & 0xF;
            }
        }
    }

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));

    return 0;
}

// ========== Chmod Event (ID 612) ==========
// Hook: security_inode_setattr — detect file permission changes

#define ATTR_MODE 1

SEC("kprobe/security_inode_setattr")
int BPF_KPROBE(elkeid_security_inode_setattr,
               struct dentry *dentry,
               struct iattr *attr)
{
    if (should_filter_event(ELKEID_EVENT_CHMOD))
        return 0;
    if (!dentry || !attr)
        return 0;

    unsigned int ia_valid = BPF_CORE_READ(attr, ia_valid);
    if (!(ia_valid & ATTR_MODE))
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_CHMOD);

    get_dentry_path(dentry, event->file_path, sizeof(event->file_path));
    event->mode = (int)BPF_CORE_READ(attr, ia_mode);

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}

// ========== Hard Link Event (ID 86) ==========
// Hook: security_inode_link (complements the symlink hook above)

SEC("kprobe/security_inode_link")
int BPF_KPROBE(elkeid_security_inode_link,
               struct dentry *old_dentry,
               struct inode *dir,
               struct dentry *new_dentry)
{
    if (should_filter_event(ELKEID_EVENT_LINK))
        return 0;
    if (!old_dentry || !new_dentry)
        return 0;

    buf_t *submit_buf = get_buf(BUF_IDX_SUBMIT);
    if (!submit_buf)
        return 0;

    file_event_t *event = (file_event_t *)submit_buf->data;
    __builtin_memset(event, 0, sizeof(*event));

    init_event_header(&event->header, ELKEID_EVENT_LINK);

    get_dentry_path(old_dentry, event->file_path, sizeof(event->file_path));
    get_dentry_path(new_dentry, event->new_path, sizeof(event->new_path));

    proc_info_t *pinfo = get_proc_info(event->header.pid);
    if (pinfo)
        __builtin_memcpy(event->exe, pinfo->exe, sizeof(event->exe));

    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, event, sizeof(*event));
    return 0;
}
