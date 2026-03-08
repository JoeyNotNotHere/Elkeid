package adapter

// Elkeid Event IDs (from plugins/driver/src/transformer/schema.rs)
const (
	EventIDOpen            = 2
	EventIDMprotect        = 10
	EventIDNanosleep       = 35
	EventIDConnect         = 42
	EventIDAccept          = 43
	EventIDBind            = 49
	EventIDExecve          = 59
	EventIDExit            = 60
	EventIDKill            = 62
	EventIDRename          = 82
	EventIDLink            = 86
	EventIDPtrace          = 101
	EventIDPrctl           = 112
	EventIDSetsid          = 157
	EventIDMount           = 165
	EventIDKillTkill       = 200
	EventIDExitGroup       = 231
	EventIDMemfdCreate     = 356
	EventIDDNS             = 601
	EventIDCreateFile      = 602
	EventIDModuleLoad      = 603
	EventIDUpdateCred      = 604
	EventIDRmdir           = 605
	EventIDUnlink          = 606
	EventIDUsermodehelper  = 607
	EventIDWrite           = 608
	EventIDWriteV2         = 609
	EventIDUdev            = 610
	EventIDPrivEscalation  = 611
	EventIDRootkitProcHook = 700 // PROC_FILE_HOOK - /proc 文件系统被篡改
	EventIDRootkitSyscall  = 701 // SYSCALL_HOOK - 系统调用表被篡改
	EventIDRootkitHidden   = 702 // LKM_HIDDEN - 隐藏内核模块
	EventIDRootkitIDT      = 703 // INTERRUPTS_HOOK - 中断处理被篡改
)

// Schema defines field names for each event ID.
// Field order matches the Rust schema.rs exactly.
var Schema = map[int][]string{
	EventIDOpen: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "flags", "mode", "file", "argv",
		"ppid_argv", "pgid_argv", "username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDMprotect: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "mprotect_prot", "owner_pid", "owner_file",
		"vm_file", "pid_tree", "argv", "ppid_argv", "pgid_argv", "username",
		"pod_name", "exe_hash",
	},
	EventIDNanosleep: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "sec", "nsec", "argv", "ppid_argv",
		"pgid_argv", "username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDConnect: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "sa_family", "dip", "dport", "sip",
		"sport", "res", "argv", "ppid_argv", "pgid_argv", "username", "pod_name",
		"exe_hash", "pid_tree",
	},
	EventIDAccept: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "sa_family", "dip", "dport", "sip",
		"sport", "res", "argv", "ppid_argv", "pgid_argv", "username", "pod_name",
		"exe_hash", "pid_tree",
	},
	EventIDBind: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "sa_family", "sip", "sport", "res",
		"argv", "ppid_argv", "pgid_argv", "username", "pod_name", "exe_hash",
		"pid_tree",
	},
	EventIDExecve: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "argv", "run_path", "stdin", "stdout",
		"dip", "dport", "sip", "sport", "sa_family", "pid_tree", "tty",
		"socket_pid", "ssh", "ld_preload", "res", "socket_argv", "ppid_argv",
		"pgid_argv", "username", "pod_name", "exe_hash",
	},
	EventIDExit: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "argv", "ppid_argv", "pgid_argv",
		"username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDKill: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "target_pid", "sig", "argv", "ppid_argv",
		"pgid_argv", "username", "pod_name", "exe_hash", "pid_tree", "target_argv",
	},
	EventIDRename: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "old_name", "new_name", "sb_id", "argv",
		"ppid_argv", "pgid_argv", "username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDLink: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "old_name", "new_name", "sb_id", "argv",
		"ppid_argv", "pgid_argv", "username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDPtrace: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "ptrace_request", "target_pid", "addr",
		"data", "pid_tree", "argv", "ppid_argv", "pgid_argv", "username",
		"pod_name", "exe_hash", "target_argv",
	},
	EventIDPrctl: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "argv", "ppid_argv", "pgid_argv",
		"username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDSetsid: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "option", "new_name", "argv", "ppid_argv",
		"pgid_argv", "username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDMount: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "pid_tree", "dev", "file_path", "fstype",
		"flags", "argv", "ppid_argv", "pgid_argv", "username", "pod_name", "exe_hash",
	},
	EventIDKillTkill: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "target_pid", "sig", "argv", "ppid_argv",
		"pgid_argv", "username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDExitGroup: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "argv", "ppid_argv", "pgid_argv",
		"username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDMemfdCreate: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "fd_name", "flags", "argv", "ppid_argv",
		"pgid_argv", "username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDDNS: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "query", "sa_family", "dip", "dport",
		"sip", "sport", "opcode", "rcode", "argv", "ppid_argv", "pgid_argv",
		"username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDCreateFile: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "file_path", "dip", "dport", "sip",
		"sport", "sa_family", "socket_pid", "sb_id", "argv", "ppid_argv",
		"pgid_argv", "username", "pod_name", "exe_hash", "pid_tree", "socket_argv",
	},
	EventIDModuleLoad: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "ko_file", "pid_tree", "run_path", "argv",
		"ppid_argv", "pgid_argv", "username", "pod_name", "exe_hash",
	},
	EventIDUpdateCred: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "pid_tree", "old_uid", "res", "argv",
		"ppid_argv", "pgid_argv", "username", "pod_name", "exe_hash", "old_username",
	},
	EventIDRmdir: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "file", "argv", "ppid_argv", "pgid_argv",
		"username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDUnlink: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "file", "argv", "ppid_argv", "pgid_argv",
		"username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDUsermodehelper: {"exe", "argv", "wait"},
	EventIDWrite: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "file", "sb_id", "argv", "ppid_argv",
		"pgid_argv", "username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDWriteV2: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "file", "sb_id", "argv", "ppid_argv",
		"pgid_argv", "username", "pod_name", "exe_hash", "pid_tree",
	},
	EventIDUdev: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "product_info", "manufacturer", "serial",
		"action", "argv", "ppid_argv", "pgid_argv", "username", "pod_name",
		"exe_hash", "pid_tree",
	},
	EventIDPrivEscalation: {
		"uid", "exe", "pid", "ppid", "pgid", "tgid", "sid", "comm", "nodename",
		"sessionid", "pns", "root_pns", "dpid", "pid_tree", "dcred", "cred",
		"argv", "ppid_argv", "pgid_argv", "username", "pod_name", "exe_hash",
		"pid_tree", "dpid_argv",
	},
	EventIDRootkitProcHook: {"module_name"},                       // 700 - /proc hook
	EventIDRootkitSyscall:  {"module_name", "syscall_number"},     // 701 - syscall hook
	EventIDRootkitHidden:   {"module_name"},                       // 702 - hidden module
	EventIDRootkitIDT:      {"module_name", "interrupt_number"},   // 703 - IDT hook
}

// Tracee event name to Elkeid event ID mapping
var TraceeToElkeid = map[string]int{
	"sched_process_exec":       EventIDExecve,
	"sched_process_exit":       EventIDExit,
	"security_socket_connect":  EventIDConnect,
	"security_socket_accept":   EventIDAccept,
	"security_socket_bind":     EventIDBind,
	"openat":                   EventIDOpen,
	"open":                     EventIDOpen,
	"kill":                     EventIDKill,
	"tkill":                    EventIDKillTkill,
	"ptrace":                   EventIDPtrace,
	"rename":                   EventIDRename,
	"renameat":                 EventIDRename,
	"link":                     EventIDLink,
	"linkat":                   EventIDLink,
	"mount":                    EventIDMount,
	"memfd_create":             EventIDMemfdCreate,
	"net_packet_dns":           EventIDDNS,
	"init_module":              EventIDModuleLoad,
	"mprotect":                 EventIDMprotect,
	"security_file_open":       EventIDCreateFile,
	"rmdir":                    EventIDRmdir,
	"unlink":                   EventIDUnlink,
	"prctl":                    EventIDPrctl,
	"commit_creds":             EventIDUpdateCred,
}

// GetSchema returns the field names for an event ID.
func GetSchema(eventID int) []string {
	if schema, ok := Schema[eventID]; ok {
		return schema
	}
	return nil
}

// GetFieldIndex returns the index of a field in an event schema.
func GetFieldIndex(eventID int, fieldName string) int {
	schema := GetSchema(eventID)
	if schema == nil {
		return -1
	}
	for i, name := range schema {
		if name == fieldName {
			return i
		}
	}
	return -1
}
