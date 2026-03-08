// SPDX-License-Identifier: GPL-2.0
// Elkeid eBPF Helpers - Extracted and simplified from Tracee
// Contains task, filesystem, and common helper functions

#ifndef __ELKEID_HELPERS_H__
#define __ELKEID_HELPERS_H__

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "types.h"

#define statfunc static __always_inline

#define bpf_memzero(dest, sz) do { (void)(dest); (void)(sz); } while(0)

#ifndef likely
#define likely(x) __builtin_expect((x), 1)
#endif

#ifndef unlikely
#define unlikely(x) __builtin_expect((x), 0)
#endif

// ========== Time Functions ==========

statfunc u64 get_current_time_ns(void)
{
    return bpf_ktime_get_ns();
}

// ========== Task Functions ==========

statfunc int get_task_flags(struct task_struct *task)
{
    return BPF_CORE_READ(task, flags);
}

statfunc u32 get_task_pid(struct task_struct *task)
{
    return BPF_CORE_READ(task, pid);
}

statfunc u32 get_task_tgid(struct task_struct *task)
{
    return BPF_CORE_READ(task, tgid);
}

statfunc u32 get_task_ppid(struct task_struct *task)
{
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    return BPF_CORE_READ(parent, tgid);
}

statfunc u32 get_task_uid(struct task_struct *task)
{
    return BPF_CORE_READ(task, cred, uid.val);
}

statfunc u32 get_task_gid(struct task_struct *task)
{
    return BPF_CORE_READ(task, cred, gid.val);
}

statfunc u32 get_task_euid(struct task_struct *task)
{
    return BPF_CORE_READ(task, cred, euid.val);
}

statfunc struct task_struct *get_parent_task(struct task_struct *task)
{
    return BPF_CORE_READ(task, real_parent);
}

statfunc struct task_struct *get_leader_task(struct task_struct *task)
{
    return BPF_CORE_READ(task, group_leader);
}

statfunc int get_task_exit_code(struct task_struct *task)
{
    return BPF_CORE_READ(task, exit_code);
}

statfunc u64 get_task_start_time(struct task_struct *task)
{
    if (bpf_core_field_exists(task->start_boottime))
        return BPF_CORE_READ(task, start_boottime);
    return BPF_CORE_READ(task, start_time);
}

// Get process group ID
statfunc u32 get_task_pgid(struct task_struct *task)
{
    struct signal_struct *sig = BPF_CORE_READ(task, signal);
    if (!sig)
        return 0;
    
    struct pid *pgrp_pid = BPF_CORE_READ(sig, pids[PIDTYPE_PGID]);
    if (!pgrp_pid)
        return 0;
    
    return BPF_CORE_READ(pgrp_pid, numbers[0].nr);
}

// Get session ID
statfunc u32 get_task_sid(struct task_struct *task)
{
    struct signal_struct *sig = BPF_CORE_READ(task, signal);
    if (!sig)
        return 0;
    
    struct pid *sid_pid = BPF_CORE_READ(sig, pids[PIDTYPE_SID]);
    if (!sid_pid)
        return 0;
    
    return BPF_CORE_READ(sid_pid, numbers[0].nr);
}

// ========== Namespace Functions ==========

statfunc u32 get_task_pid_ns_id(struct task_struct *task)
{
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
    if (!nsp)
        return 0;
    
    struct pid_namespace *pid_ns = BPF_CORE_READ(nsp, pid_ns_for_children);
    if (!pid_ns)
        return 0;
    
    return BPF_CORE_READ(pid_ns, ns.inum);
}

statfunc u32 get_task_mnt_ns_id(struct task_struct *task)
{
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
    if (!nsp)
        return 0;
    
    struct mnt_namespace *mnt_ns = BPF_CORE_READ(nsp, mnt_ns);
    if (!mnt_ns)
        return 0;
    
    return BPF_CORE_READ(mnt_ns, ns.inum);
}

// Get hostname
statfunc char *get_task_uts_name(struct task_struct *task)
{
    struct nsproxy *nsp = BPF_CORE_READ(task, nsproxy);
    if (!nsp)
        return NULL;
    
    struct uts_namespace *uts = BPF_CORE_READ(nsp, uts_ns);
    if (!uts)
        return NULL;
    
    return (char *)BPF_CORE_READ(uts, name.nodename);
}

// ========== File/Filesystem Functions ==========

statfunc struct file *get_struct_file_from_fd(u64 fd_num)
{
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (!task)
        return NULL;
    
    struct files_struct *files = BPF_CORE_READ(task, files);
    if (!files)
        return NULL;
    
    struct fdtable *fdt = BPF_CORE_READ(files, fdt);
    if (!fdt)
        return NULL;
    
    struct file **fd_array = BPF_CORE_READ(fdt, fd);
    if (!fd_array)
        return NULL;
    
    struct file *file = NULL;
    bpf_core_read(&file, sizeof(file), &fd_array[fd_num]);
    return file;
}

statfunc unsigned short get_inode_mode_from_file(struct file *file)
{
    if (!file)
        return 0;
    return BPF_CORE_READ(file, f_inode, i_mode);
}

statfunc unsigned long get_inode_nr_from_file(struct file *file)
{
    if (!file)
        return 0;
    return BPF_CORE_READ(file, f_inode, i_ino);
}

statfunc dev_t get_dev_from_file(struct file *file)
{
    if (!file)
        return 0;
    return BPF_CORE_READ(file, f_inode, i_sb, s_dev);
}

// ========== TTY Functions ==========

statfunc struct tty_struct *get_task_tty(struct task_struct *task)
{
    struct signal_struct *sig = BPF_CORE_READ(task, signal);
    if (!sig)
        return NULL;
    return BPF_CORE_READ(sig, tty);
}

statfunc int get_tty_name(struct task_struct *task, char *buf, int size)
{
    struct tty_struct *tty = get_task_tty(task);
    if (!tty) {
        buf[0] = '-';
        buf[1] = '1';
        buf[2] = '\0';
        return 0;
    }
    bpf_core_read_str(buf, size, tty->name);
    return 0;
}

// ========== Credential Functions ==========

statfunc const struct cred *get_task_cred(struct task_struct *task)
{
    return BPF_CORE_READ(task, cred);
}

statfunc const struct cred *get_task_real_cred(struct task_struct *task)
{
    return BPF_CORE_READ(task, real_cred);
}

// ========== Event Header Initialization ==========

statfunc void init_event_header(event_header_t *hdr, u32 event_id)
{
    hdr->timestamp = bpf_ktime_get_ns();
    hdr->event_id = event_id;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    hdr->pid = pid_tgid >> 32;
    hdr->tid = (u32)pid_tgid;

    u64 uid_gid = bpf_get_current_uid_gid();
    hdr->uid = (u32)uid_gid;
    hdr->gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    // ppid: task->real_parent->tgid (two separate reads to help verifier)
    struct task_struct *parent = BPF_CORE_READ(task, real_parent);
    hdr->ppid = BPF_CORE_READ(parent, tgid);

    // pgid: task->signal->pids[PIDTYPE_PGID]->numbers[0].nr
    hdr->pgid = get_task_pgid(task);

    // sid: task->signal->pids[PIDTYPE_SID]->numbers[0].nr
    hdr->sid = get_task_sid(task);

    // pid namespace inode number
    hdr->pid_ns = get_task_pid_ns_id(task);

    bpf_get_current_comm(&hdr->comm, sizeof(hdr->comm));
}

// ========== String Functions ==========

statfunc int str_has_prefix(const char *prefix, const char *str, int n)
{
    int i;
    #pragma unroll
    for (i = 0; i < n && i < 64; i++) {
        if (!prefix[i])
            return 1;
        if (prefix[i] != str[i])
            return 0;
    }
    return prefix[n] == '\0';
}

// ========== Event Filtering ==========

// Returns 1 if the event should be SKIPPED (filtered out), 0 if allowed.
statfunc int should_filter_event(u32 event_id)
{
    u8 *enabled = bpf_map_lookup_elem(&event_filter, &event_id);
    if (enabled && *enabled == 0)
        return 1;

    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    u8 *pid_wl = bpf_map_lookup_elem(&pid_filter, &tgid);
    if (pid_wl)
        return 1;

    return 0;
}

#endif /* __ELKEID_HELPERS_H__ */
