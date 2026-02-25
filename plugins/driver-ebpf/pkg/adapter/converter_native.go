package adapter

import (
	"os"
	"strconv"
	"strings"
	"time"

	"driver-ebpf/pkg/cache"
	"driver-ebpf/pkg/loader"
	"plugins"
)

// NativeConverter converts native BPF events to Elkeid binary format.
type NativeConverter struct {
	encoder     *Encoder
	procTree    *cache.ProcTreeCache
	socketCache *cache.SocketCache
	userCache   *cache.UserCache
	hostname    string
	rootPidNS   string
}

// NewNativeConverter creates a new native event converter.
func NewNativeConverter(
	procTree *cache.ProcTreeCache,
	socketCache *cache.SocketCache,
	userCache *cache.UserCache,
) *NativeConverter {
	hostname, _ := os.Hostname()
	rootPidNS := ""
	if procTree != nil {
		rootPidNS = strconv.FormatUint(procTree.GetRootPidNs(), 10)
	}

	return &NativeConverter{
		encoder:     NewEncoder(),
		procTree:    procTree,
		socketCache: socketCache,
		userCache:   userCache,
		hostname:    hostname,
		rootPidNS:   rootPidNS,
	}
}

// Convert converts a native BPF event to Elkeid binary format.
func (c *NativeConverter) Convert(event loader.Event) ([]byte, error) {
	header := event.GetHeader()

	switch header.EventID {
	case loader.EventIDExecve:
		return c.ConvertExecve(event.(*loader.ExecveEvent))
	case loader.EventIDExit, loader.EventIDExitGroup:
		return c.ConvertExit(event.(*loader.ExitEvent), int(header.EventID))
	case loader.EventIDConnect:
		return c.ConvertConnect(event.(*loader.NetEvent))
	case loader.EventIDAccept:
		return c.ConvertAccept(event.(*loader.NetEvent))
	case loader.EventIDBind:
		return c.ConvertBind(event.(*loader.NetEvent))
	case loader.EventIDOpen:
		return c.ConvertOpen(event.(*loader.FileEvent))
	case loader.EventIDKill, loader.EventIDKillTkill:
		return c.ConvertKill(event.(*loader.FileEvent), int(header.EventID))
	case loader.EventIDPtrace:
		return c.ConvertPtrace(event.(*loader.FileEvent))
	case loader.EventIDPrctl:
		return c.ConvertPrctl(event.(*loader.FileEvent))
	case loader.EventIDRename:
		return c.ConvertRename(event.(*loader.FileEvent))
	case loader.EventIDLink:
		return c.ConvertLink(event.(*loader.FileEvent))
	case loader.EventIDUnlink:
		return c.ConvertUnlink(event.(*loader.FileEvent))
	case loader.EventIDMount:
		return c.ConvertMount(event.(*loader.FileEvent))
	case loader.EventIDMprotect:
		return c.ConvertMprotect(event.(*loader.FileEvent))
	case loader.EventIDMemfdCreate:
		return c.ConvertMemfdCreate(event.(*loader.FileEvent))
	case loader.EventIDModuleLoad:
		return c.ConvertModuleLoad(event.(*loader.ModuleEvent))
	case loader.EventIDUpdateCred:
		return c.ConvertUpdateCred(event.(*loader.CredEvent))
	case loader.EventIDCreateFile:
		return c.ConvertCreateFile(event.(*loader.FileEvent))
	case loader.EventIDUsermodehelper:
		return c.ConvertUsermodehelper(event.(*loader.FileEvent))
	case loader.EventIDSetsid:
		return c.ConvertSetsid(event.(*loader.FileEvent))
	case loader.EventIDRmdir:
		return c.ConvertRmdir(event.(*loader.FileEvent))
	case loader.EventIDWrite:
		return c.ConvertWrite(event.(*loader.FileEvent))
	case loader.EventIDDNS:
		return c.ConvertDNS(event.(*loader.DNSEvent))
	default:
		return nil, nil
	}
}

// ConvertToRecords converts a BPF event into one or more records.
// Most events produce one record; update_cred may also produce a privilege_escalation record.
func (c *NativeConverter) ConvertToRecords(event loader.Event) []*plugins.Record {
	rec := c.ConvertToRecord(event)
	if rec == nil {
		return nil
	}
	records := []*plugins.Record{rec}

	if credEvent, ok := event.(*loader.CredEvent); ok && IsPrivilegeEscalation(credEvent) {
		privRec := c.convertPrivEscalationRecord(credEvent)
		if privRec != nil {
			records = append(records, privRec)
		}
	}
	return records
}

func (c *NativeConverter) convertPrivEscalationRecord(event *loader.CredEvent) *plugins.Record {
	fields := make(map[string]string)
	fields["uid"] = strconv.FormatUint(uint64(event.Header.UID), 10)
	fields["exe"] = event.GetExe()
	fields["pid"] = strconv.FormatUint(uint64(event.Header.PID), 10)
	fields["ppid"] = strconv.FormatUint(uint64(event.Header.PPID), 10)
	fields["comm"] = event.Header.GetComm()
	fields["nodename"] = c.hostname
	fields["pns"] = strconv.FormatUint(uint64(event.Header.PidNS), 10)
	fields["root_pns"] = c.rootPidNS
	fields["old_uid"] = strconv.FormatUint(uint64(event.OldUID), 10)
	fields["new_uid"] = strconv.FormatUint(uint64(event.NewUID), 10)
	fields["old_euid"] = strconv.FormatUint(uint64(event.OldEUID), 10)
	fields["new_euid"] = strconv.FormatUint(uint64(event.NewEUID), 10)
	c.enrichFieldsWithCache(int(event.Header.PID), fields)

	return &plugins.Record{
		DataType:  int32(EventIDPrivEscalation),
		Timestamp: time.Now().Unix(),
		Data:      &plugins.Payload{Fields: fields},
	}
}

// ConvertToRecord converts a native BPF event to plugins.Record format.
// This format is used by Go plugins to communicate with Elkeid Agent.
func (c *NativeConverter) ConvertToRecord(event loader.Event) *plugins.Record {
	header := event.GetHeader()
	eventID := int(header.EventID)

	// Get schema for this event
	schema := GetSchema(eventID)
	if schema == nil {
		return nil
	}

	// Build fields map
	fields := make(map[string]string)

	// Fill common fields
	fields["uid"] = strconv.FormatUint(uint64(header.UID), 10)
	fields["pid"] = strconv.FormatUint(uint64(header.PID), 10)
	fields["ppid"] = strconv.FormatUint(uint64(header.PPID), 10)
	fields["pgid"] = strconv.FormatUint(uint64(header.PGID), 10)
	fields["tgid"] = strconv.FormatUint(uint64(header.TID), 10)
	fields["sid"] = strconv.FormatUint(uint64(header.SID), 10)
	fields["comm"] = header.GetComm()
	fields["nodename"] = c.hostname
	fields["sessionid"] = strconv.FormatUint(uint64(header.SID), 10)
	fields["pns"] = strconv.FormatUint(uint64(header.PidNS), 10)
	fields["root_pns"] = c.rootPidNS

	// Fill event-specific fields
	switch e := event.(type) {
	case *loader.ExecveEvent:
		fields["exe"] = e.GetExe()
		fields["argv"] = e.GetArgv()

	case *loader.ExitEvent:
		fields["exe"] = e.GetExe()
		fields["exit_code"] = strconv.Itoa(int(e.ExitCode))

	case *loader.NetEvent:
		fields["exe"] = e.GetExe()
		fields["sa_family"] = strconv.Itoa(int(e.SaFamily))
		fields["sip"] = e.GetSrcIP().String()
		fields["sport"] = strconv.Itoa(int(e.SPort))
		fields["dip"] = e.GetDstIP().String()
		fields["dport"] = strconv.Itoa(int(e.DPort))
		fields["res"] = strconv.Itoa(int(e.Ret))

	case *loader.FileEvent:
		fields["exe"] = e.GetExe()
		fields["file"] = e.GetFilePath()
		fields["flags"] = strconv.Itoa(int(e.Flags))

	case *loader.ModuleEvent:
		fields["exe"] = e.GetExe()
		fields["module_name"] = e.GetModuleName()

	case *loader.CredEvent:
		fields["exe"] = e.GetExe()
		fields["old_uid"] = strconv.FormatUint(uint64(e.OldUID), 10)
		fields["new_uid"] = strconv.FormatUint(uint64(e.NewUID), 10)
		fields["old_euid"] = strconv.FormatUint(uint64(e.OldEUID), 10)
		fields["new_euid"] = strconv.FormatUint(uint64(e.NewEUID), 10)

	case *loader.DNSEvent:
		fields["exe"] = e.GetExe()
		fields["query"] = e.GetQuery()
		fields["sa_family"] = strconv.Itoa(int(e.SaFamily))
		fields["sip"] = e.GetSrcIP().String()
		fields["sport"] = strconv.Itoa(int(e.SPort))
		fields["dip"] = e.GetDstIP().String()
		fields["dport"] = strconv.Itoa(int(e.DPort))
		fields["opcode"] = strconv.Itoa(int(e.Opcode))
		fields["rcode"] = strconv.Itoa(int(e.Rcode))
	}

	// Enrich with cache data
	c.enrichFieldsWithCache(int(header.PID), fields)

	return &plugins.Record{
		DataType:  int32(eventID),
		Timestamp: time.Now().Unix(),
		Data: &plugins.Payload{
			Fields: fields,
		},
	}
}

// enrichFieldsWithCache adds cached data to fields map.
func (c *NativeConverter) enrichFieldsWithCache(pid int, fields map[string]string) {
	// Get username
	if c.userCache != nil {
		uidStr := fields["uid"]
		if uid, err := strconv.Atoi(uidStr); err == nil {
			fields["username"] = c.userCache.GetUsername(uid)
		}
	}

	// Build pid_tree
	if c.procTree != nil {
		fields["pid_tree"] = c.procTree.BuildPidTree(pid, 10)
	}

	// Get ppid_argv and pgid_argv
	if c.procTree != nil {
		ppidStr := fields["ppid"]
		if ppid, err := strconv.Atoi(ppidStr); err == nil {
			if info, ok := c.procTree.Get(ppid); ok {
				fields["ppid_argv"] = info.Exe
			}
		}

		pgidStr := fields["pgid"]
		if pgid, err := strconv.Atoi(pgidStr); err == nil {
			if info, ok := c.procTree.Get(pgid); ok {
				fields["pgid_argv"] = info.Exe
			}
		}
	}
}

// fillCommonFields fills common fields (0-11) for most events.
func (c *NativeConverter) fillCommonFields(header *loader.EventHeader, exe string, values []string) {
	values[0] = strconv.FormatUint(uint64(header.UID), 10) // uid
	values[1] = exe                                        // exe
	values[2] = strconv.FormatUint(uint64(header.PID), 10) // pid
	values[3] = strconv.FormatUint(uint64(header.PPID), 10) // ppid
	values[4] = strconv.FormatUint(uint64(header.PGID), 10) // pgid
	values[5] = strconv.FormatUint(uint64(header.TID), 10)  // tgid
	values[6] = strconv.FormatUint(uint64(header.SID), 10)  // sid
	values[7] = header.GetComm()                            // comm
	values[8] = c.hostname                                  // nodename
	values[9] = strconv.FormatUint(uint64(header.SID), 10)  // sessionid (same as sid)
	values[10] = strconv.FormatUint(uint64(header.PidNS), 10) // pns
	values[11] = c.rootPidNS                                  // root_pns
}

// enrichWithCache adds cache-derived fields.
func (c *NativeConverter) enrichWithCache(pid uint32, values []string, pidTreeIdx, usernameIdx, podNameIdx int) {
	// pid_tree (limit to 10 levels)
	if pidTreeIdx >= 0 && c.procTree != nil {
		values[pidTreeIdx] = c.procTree.BuildPidTree(int(pid), 10)
	}

	// username
	if usernameIdx >= 0 && c.userCache != nil {
		// UID is in values[0]
		if uid, err := strconv.Atoi(values[0]); err == nil {
			values[usernameIdx] = c.userCache.GetUsername(uid)
		}
	}

	// pod_name (placeholder)
	if podNameIdx >= 0 {
		values[podNameIdx] = ""
	}
}

// ConvertExecve converts an execve event.
func (c *NativeConverter) ConvertExecve(event *loader.ExecveEvent) ([]byte, error) {
	// Schema: [uid, exe, pid, ppid, pgid, tgid, sid, comm, nodename, sessionid, pns, root_pns,
	//          argv, run_path, stdin, stdout, dip, dport, sip, sport, sa_family, pid_tree, tty,
	//          socket_pid, ssh, ld_preload, res, socket_argv, ppid_argv, pgid_argv, username, pod_name, exe_hash]
	values := make([]string, 33)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	// argv (12)
	values[12] = strings.Join(event.GetArgvList(), " ")

	// run_path / cwd (13)
	values[13] = event.GetCwd()

	// stdin (14)
	values[14] = event.GetStdinPath()

	// stdout (15) - Elkeid specific
	values[15] = event.GetStdoutPath()

	// Network fields (16-20) - from socket cache
	if c.socketCache != nil && c.procTree != nil {
		if sockInfo, socketPID := c.socketCache.FindProcessSocket(int(event.Header.PID), c.procTree, 4); sockInfo != nil {
			values[16] = cache.FormatIPv4(sockInfo.DstIP)            // dip
			values[17] = strconv.Itoa(int(sockInfo.DstPort))         // dport
			values[18] = cache.FormatIPv4(sockInfo.SrcIP)            // sip
			values[19] = strconv.Itoa(int(sockInfo.SrcPort))         // sport
			values[20] = strconv.Itoa(int(sockInfo.Family))          // sa_family
			values[23] = strconv.Itoa(socketPID)                     // socket_pid
		}
	}

	// pid_tree (21)
	c.enrichWithCache(event.Header.PID, values, 21, 30, 31)

	// tty (22)
	values[22] = event.GetTTY()

	// ssh, ld_preload from /proc/<pid>/environ (24, 25)
	ssh, ldPreload := readEnvVars(int(event.Header.PID))
	values[24] = ssh
	values[25] = ldPreload

	// res (26)
	values[26] = strconv.Itoa(int(event.Ret))

	// socket_argv, ppid_argv, pgid_argv (27, 28, 29)
	if c.procTree != nil {
		values[28] = c.procTree.GetParentArgv(int(event.Header.PPID))
		values[29] = c.procTree.GetParentArgv(int(event.Header.PGID))
	}

	// exe_hash (32) - computed in Go if needed
	values[32] = ""

	return c.encoder.Encode(EventIDExecve, values)
}

// ConvertExit converts an exit event.
func (c *NativeConverter) ConvertExit(event *loader.ExitEvent, eventID int) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	// exit_code (12)
	values[12] = strconv.Itoa(int(event.ExitCode))

	// pid_tree (13)
	c.enrichWithCache(event.Header.PID, values, 13, 18, 19)

	return c.encoder.Encode(eventID, values)
}

// ConvertConnect converts a connect event.
func (c *NativeConverter) ConvertConnect(event *loader.NetEvent) ([]byte, error) {
	values := make([]string, 25)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	// Network fields
	values[12] = strconv.Itoa(int(event.SaFamily)) // sa_family
	values[13] = event.GetDstIP().String()         // dip
	values[14] = strconv.Itoa(int(event.DPort))    // dport
	values[15] = event.GetSrcIP().String()         // sip
	values[16] = strconv.Itoa(int(event.SPort))    // sport
	values[17] = strconv.Itoa(int(event.Ret))      // res

	c.enrichWithCache(event.Header.PID, values, 22, 23, 24)

	return c.encoder.Encode(EventIDConnect, values)
}

// ConvertAccept converts an accept event.
func (c *NativeConverter) ConvertAccept(event *loader.NetEvent) ([]byte, error) {
	values := make([]string, 25)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = strconv.Itoa(int(event.SaFamily))
	values[13] = event.GetDstIP().String()
	values[14] = strconv.Itoa(int(event.DPort))
	values[15] = event.GetSrcIP().String()
	values[16] = strconv.Itoa(int(event.SPort))
	values[17] = strconv.Itoa(int(event.Ret))

	c.enrichWithCache(event.Header.PID, values, 22, 23, 24)

	return c.encoder.Encode(EventIDAccept, values)
}

// ConvertBind converts a bind event.
func (c *NativeConverter) ConvertBind(event *loader.NetEvent) ([]byte, error) {
	values := make([]string, 25)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = strconv.Itoa(int(event.SaFamily))
	values[13] = event.GetSrcIP().String() // For bind, sip is the bound address
	values[14] = strconv.Itoa(int(event.SPort))
	values[15] = strconv.Itoa(int(event.Ret))

	c.enrichWithCache(event.Header.PID, values, 22, 23, 24)

	return c.encoder.Encode(EventIDBind, values)
}

// ConvertOpen converts an open event.
func (c *NativeConverter) ConvertOpen(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 22)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = strconv.Itoa(int(event.Flags)) // flags
	values[13] = strconv.Itoa(int(event.Mode))  // mode
	values[14] = event.GetFilePath()            // file

	c.enrichWithCache(event.Header.PID, values, 21, 18, 19)

	return c.encoder.Encode(EventIDOpen, values)
}

// ConvertKill converts a kill/tkill event.
func (c *NativeConverter) ConvertKill(event *loader.FileEvent, eventID int) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = strconv.Itoa(int(event.Flags)) // target_pid
	values[13] = strconv.Itoa(int(event.Mode))  // signal

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(eventID, values)
}

// ConvertPtrace converts a ptrace event.
func (c *NativeConverter) ConvertPtrace(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = strconv.Itoa(int(event.Flags)) // request
	values[13] = strconv.Itoa(int(event.Mode))  // target_pid

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(EventIDPtrace, values)
}

// ConvertPrctl converts a prctl event.
func (c *NativeConverter) ConvertPrctl(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = strconv.Itoa(int(event.Flags)) // option

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(EventIDPrctl, values)
}

// ConvertRename converts a rename event.
func (c *NativeConverter) ConvertRename(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = event.GetFilePath() // old_name
	values[13] = event.GetNewPath()  // new_name

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(EventIDRename, values)
}

// ConvertLink converts a link/symlink event.
func (c *NativeConverter) ConvertLink(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = event.GetFilePath() // link_path
	values[13] = event.GetNewPath()  // target

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(EventIDLink, values)
}

// ConvertUnlink converts an unlink event.
func (c *NativeConverter) ConvertUnlink(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = event.GetFilePath() // file

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(EventIDUnlink, values)
}

// ConvertMount converts a mount event.
func (c *NativeConverter) ConvertMount(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = event.GetFilePath() // dev_name
	values[13] = event.GetNewPath()  // mount_point
	values[14] = strconv.Itoa(int(event.Flags)) // flags

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(EventIDMount, values)
}

// ConvertMprotect converts an mprotect event.
func (c *NativeConverter) ConvertMprotect(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 23)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = strconv.Itoa(int(event.Flags)) // prot
	values[13] = strconv.Itoa(int(event.Mode))  // reqprot
	values[14] = event.GetFilePath()            // vm_file

	c.enrichWithCache(event.Header.PID, values, 16, 20, 21)

	return c.encoder.Encode(EventIDMprotect, values)
}

// ConvertMemfdCreate converts a memfd_create event.
func (c *NativeConverter) ConvertMemfdCreate(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = event.GetFilePath()            // name
	values[13] = strconv.Itoa(int(event.Flags)) // flags

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(EventIDMemfdCreate, values)
}

// ConvertModuleLoad converts a module load event.
func (c *NativeConverter) ConvertModuleLoad(event *loader.ModuleEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = event.GetModuleName() // module_name
	values[13] = event.GetKoFile()     // ko_file

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(EventIDModuleLoad, values)
}

// ConvertUpdateCred converts an update_cred event.
func (c *NativeConverter) ConvertUpdateCred(event *loader.CredEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = strconv.FormatUint(uint64(event.OldUID), 10)
	values[13] = strconv.FormatUint(uint64(event.NewUID), 10)
	values[14] = strconv.FormatUint(uint64(event.OldEUID), 10)
	values[15] = strconv.FormatUint(uint64(event.NewEUID), 10)

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(EventIDUpdateCred, values)
}

// IsPrivilegeEscalation checks if a credential change is a privilege escalation.
func IsPrivilegeEscalation(event *loader.CredEvent) bool {
	return (event.OldUID != 0 && event.NewUID == 0) ||
		(event.OldEUID != 0 && event.NewEUID == 0)
}

// ConvertPrivEscalation generates a privilege_escalation event (ID 611)
// from a credential change where uid/euid goes from non-root to root.
func (c *NativeConverter) ConvertPrivEscalation(event *loader.CredEvent) ([]byte, error) {
	values := make([]string, 24)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = strconv.FormatUint(uint64(event.Header.PID), 10) // dpid (destination pid)
	c.enrichWithCache(event.Header.PID, values, 13, 19, 20)      // pid_tree(13), username(19), pod_name(20)

	oldCred := strconv.FormatUint(uint64(event.OldUID), 10) + "," + strconv.FormatUint(uint64(event.OldEUID), 10)
	newCred := strconv.FormatUint(uint64(event.NewUID), 10) + "," + strconv.FormatUint(uint64(event.NewEUID), 10)
	values[14] = oldCred // dcred (old credentials)
	values[15] = newCred // cred (new credentials)

	return c.encoder.Encode(EventIDPrivEscalation, values)
}

// ConvertCreateFile converts a create_file event (ID 602).
func (c *NativeConverter) ConvertCreateFile(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = event.GetFilePath()            // file
	values[13] = strconv.Itoa(int(event.Mode))  // mode

	c.enrichWithCache(event.Header.PID, values, 17, 18, 19)

	return c.encoder.Encode(EventIDCreateFile, values)
}

// ConvertUsermodehelper converts a usermodehelper event.
func (c *NativeConverter) ConvertUsermodehelper(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 15)

	c.fillCommonFields(&event.Header, "", values)

	values[12] = event.GetFilePath() // helper_path

	return c.encoder.Encode(EventIDUsermodehelper, values)
}

// ConvertSetsid converts a setsid event.
func (c *NativeConverter) ConvertSetsid(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 21)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	// index 12=option, 13=new_name, 14=argv, 15=ppid_argv, 16=pgid_argv, 17=username
	c.enrichWithCache(event.Header.PID, values, 15, 16, 17)

	return c.encoder.Encode(EventIDSetsid, values)
}

// ConvertRmdir converts a rmdir event.
func (c *NativeConverter) ConvertRmdir(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 20)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = event.GetFilePath() // file (dir_path)
	// 13=argv, 14=ppid_argv, 15=pgid_argv, 16=username
	c.enrichWithCache(event.Header.PID, values, 14, 15, 16)

	return c.encoder.Encode(EventIDRmdir, values)
}

// ConvertWrite converts a write event.
func (c *NativeConverter) ConvertWrite(event *loader.FileEvent) ([]byte, error) {
	values := make([]string, 21)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = event.GetFilePath()            // file
	values[13] = strconv.Itoa(int(event.Flags)) // sb_id
	// 14=argv, 15=ppid_argv, 16=pgid_argv, 17=username
	c.enrichWithCache(event.Header.PID, values, 15, 16, 17)

	return c.encoder.Encode(EventIDWrite, values)
}

// ConvertDNS converts a DNS query event.
func (c *NativeConverter) ConvertDNS(event *loader.DNSEvent) ([]byte, error) {
	values := make([]string, 27)

	c.fillCommonFields(&event.Header, event.GetExe(), values)

	values[12] = parseDNSLabels(event.Query[:]) // query (converted from label format)
	values[13] = strconv.Itoa(int(event.SaFamily))
	values[14] = event.GetDstIP().String()
	values[15] = strconv.Itoa(int(event.DPort))
	values[16] = event.GetSrcIP().String()
	values[17] = strconv.Itoa(int(event.SPort))
	values[18] = strconv.Itoa(int(event.Opcode))
	values[19] = strconv.Itoa(int(event.Rcode))
	c.enrichWithCache(event.Header.PID, values, 21, 22, 23)

	return c.encoder.Encode(EventIDDNS, values)
}

// readEnvVars reads SSH_CONNECTION and LD_PRELOAD from /proc/<pid>/environ.
func readEnvVars(pid int) (ssh, ldPreload string) {
	data, err := os.ReadFile("/proc/" + strconv.Itoa(pid) + "/environ")
	if err != nil {
		return "", ""
	}
	for _, env := range strings.Split(string(data), "\x00") {
		if strings.HasPrefix(env, "SSH_CONNECTION=") {
			ssh = strings.TrimPrefix(env, "SSH_CONNECTION=")
		} else if strings.HasPrefix(env, "LD_PRELOAD=") {
			ldPreload = strings.TrimPrefix(env, "LD_PRELOAD=")
		}
	}
	return
}

// parseDNSLabels converts DNS wire format labels to dot-separated domain name.
// Input: \x03www\x06google\x03com\x00 → Output: "www.google.com"
func parseDNSLabels(data []byte) string {
	var parts []string
	i := 0
	for i < len(data) {
		labelLen := int(data[i])
		if labelLen == 0 {
			break
		}
		i++
		if i+labelLen > len(data) {
			break
		}
		parts = append(parts, string(data[i:i+labelLen]))
		i += labelLen
	}
	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, ".")
}
