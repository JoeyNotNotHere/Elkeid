// Package loader provides BPF program loading and event reading.
package loader

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

// Constants matching BPF types.h
const (
	TaskCommLen  = 16
	MaxPathLen   = 256
	MaxArgsLen   = 256
	MaxStringLen = 4096
)

// Event IDs matching BPF types.h
const (
	EventIDOpen           = 2
	EventIDMprotect       = 10
	EventIDConnect        = 42
	EventIDAccept         = 43
	EventIDBind           = 49
	EventIDExecve         = 59
	EventIDExit           = 60
	EventIDKill           = 62
	EventIDRename         = 82
	EventIDLink           = 86
	EventIDPtrace         = 101
	EventIDPrctl          = 112
	EventIDSetsid         = 157
	EventIDMount          = 165
	EventIDKillTkill      = 200
	EventIDExitGroup      = 231
	EventIDMemfdCreate    = 356
	EventIDDNS            = 601
	EventIDCreateFile     = 602
	EventIDModuleLoad     = 603
	EventIDUpdateCred     = 604
	EventIDRmdir          = 605
	EventIDUnlink         = 606
	EventIDUsermodehelper = 607
	EventIDWrite          = 608
	EventIDChmod          = 612
)

// EventHeader is the common header for all events.
// Must match event_header_t in types.h
type EventHeader struct {
	Timestamp uint64
	EventID   uint32
	PID       uint32
	TID       uint32
	PPID      uint32
	UID       uint32
	GID       uint32
	PGID      uint32
	SID       uint32
	PidNS     uint32
	Comm      [TaskCommLen]byte
}

// GetComm returns the process name as a string.
func (h *EventHeader) GetComm() string {
	return cStringToGo(h.Comm[:])
}

// ExecveEvent represents an execve event.
// Must match execve_event_t in types.h
type ExecveEvent struct {
	Header     EventHeader
	Exe        [MaxPathLen]byte
	Cwd        [MaxPathLen]byte
	StdinPath  [MaxPathLen]byte
	StdoutPath [MaxPathLen]byte
	TTY        [32]byte
	Argv       [MaxArgsLen]byte
	Argc       int32
	Ret        int32
	StdinType  uint32
	StdoutType uint32
}

// GetExe returns the executable path as a string.
func (e *ExecveEvent) GetExe() string {
	return cStringToGo(e.Exe[:])
}

// GetCwd returns the current working directory as a string.
func (e *ExecveEvent) GetCwd() string {
	return cStringToGo(e.Cwd[:])
}

// GetStdinPath returns the stdin path as a string.
func (e *ExecveEvent) GetStdinPath() string {
	return cStringToGo(e.StdinPath[:])
}

// GetStdoutPath returns the stdout path as a string.
func (e *ExecveEvent) GetStdoutPath() string {
	return cStringToGo(e.StdoutPath[:])
}

// GetTTY returns the TTY name as a string.
func (e *ExecveEvent) GetTTY() string {
	return cStringToGo(e.TTY[:])
}

// GetArgv returns the arguments as a string (null-separated).
func (e *ExecveEvent) GetArgv() string {
	return cStringToGo(e.Argv[:])
}

// GetArgvList returns the arguments as a slice of strings.
func (e *ExecveEvent) GetArgvList() []string {
	data := e.Argv[:]
	var args []string
	for i := 0; i < int(e.Argc) && len(data) > 0; i++ {
		idx := bytes.IndexByte(data, 0)
		if idx == -1 {
			args = append(args, string(data))
			break
		}
		if idx > 0 {
			args = append(args, string(data[:idx]))
		}
		data = data[idx+1:]
	}
	return args
}

// ExitEvent represents an exit/exit_group event.
// Must match exit_event_t in types.h
type ExitEvent struct {
	Header   EventHeader
	Exe      [MaxPathLen]byte
	ExitCode int32
}

// GetExe returns the executable path.
func (e *ExitEvent) GetExe() string {
	return cStringToGo(e.Exe[:])
}

// NetEvent represents a network event (connect/accept/bind).
// Must match net_event_t in types.h
type NetEvent struct {
	Header   EventHeader
	Exe      [MaxPathLen]byte
	SaFamily uint16
	SPort    uint16
	DPort    uint16
	SIP      [16]byte
	DIP      [16]byte
	Ret      int32
}

// GetExe returns the executable path.
func (e *NetEvent) GetExe() string {
	return cStringToGo(e.Exe[:])
}

// GetSrcIP returns the source IP address.
func (e *NetEvent) GetSrcIP() net.IP {
	if e.SaFamily == 2 { // AF_INET
		return net.IP(e.SIP[:4])
	}
	return net.IP(e.SIP[:])
}

// GetDstIP returns the destination IP address.
func (e *NetEvent) GetDstIP() net.IP {
	if e.SaFamily == 2 { // AF_INET
		return net.IP(e.DIP[:4])
	}
	return net.IP(e.DIP[:])
}

// FileEvent represents a file event (open/write/rename/unlink).
// Must match file_event_t in types.h
type FileEvent struct {
	Header   EventHeader
	Exe      [MaxPathLen]byte
	FilePath [MaxPathLen]byte
	NewPath  [MaxPathLen]byte
	Flags    int32
	Mode     int32
	Ret      int32
}

// GetExe returns the executable path.
func (e *FileEvent) GetExe() string {
	return cStringToGo(e.Exe[:])
}

// GetFilePath returns the file path.
func (e *FileEvent) GetFilePath() string {
	return cStringToGo(e.FilePath[:])
}

// GetNewPath returns the new path (for rename).
func (e *FileEvent) GetNewPath() string {
	return cStringToGo(e.NewPath[:])
}

// ModuleEvent represents a kernel module load event.
// Must match module_event_t in types.h
type ModuleEvent struct {
	Header     EventHeader
	Exe        [MaxPathLen]byte
	ModuleName [64]byte
	KoFile     [MaxPathLen]byte
}

// GetExe returns the executable path.
func (e *ModuleEvent) GetExe() string {
	return cStringToGo(e.Exe[:])
}

// GetModuleName returns the module name.
func (e *ModuleEvent) GetModuleName() string {
	return cStringToGo(e.ModuleName[:])
}

// GetKoFile returns the kernel object file path.
func (e *ModuleEvent) GetKoFile() string {
	return cStringToGo(e.KoFile[:])
}

// CredEvent represents a credential change event.
// Must match cred_event_t in types.h
type CredEvent struct {
	Header  EventHeader
	Exe     [MaxPathLen]byte
	OldUID  uint32
	NewUID  uint32
	OldEUID uint32
	NewEUID uint32
}

// GetExe returns the executable path.
func (e *CredEvent) GetExe() string {
	return cStringToGo(e.Exe[:])
}

// DNSEvent represents a DNS query event.
// Must match dns_event_t in types.h
type DNSEvent struct {
	Header   EventHeader
	Exe      [MaxPathLen]byte
	Query    [256]byte
	SaFamily uint16
	SPort    uint16
	DPort    uint16
	SIP      [16]byte
	DIP      [16]byte
	Opcode   uint16
	Rcode    uint16
}

// GetExe returns the executable path.
func (e *DNSEvent) GetExe() string {
	return cStringToGo(e.Exe[:])
}

// GetQuery returns the DNS query string.
func (e *DNSEvent) GetQuery() string {
	return cStringToGo(e.Query[:])
}

// GetSrcIP returns the source IP address.
func (e *DNSEvent) GetSrcIP() net.IP {
	if e.SaFamily == 2 { // AF_INET
		return net.IP(e.SIP[:4])
	}
	return net.IP(e.SIP[:])
}

// GetDstIP returns the destination IP address.
func (e *DNSEvent) GetDstIP() net.IP {
	if e.SaFamily == 2 { // AF_INET
		return net.IP(e.DIP[:4])
	}
	return net.IP(e.DIP[:])
}

// Event is the interface for all BPF events.
type Event interface {
	GetHeader() *EventHeader
}

func (e *ExecveEvent) GetHeader() *EventHeader { return &e.Header }
func (e *ExitEvent) GetHeader() *EventHeader   { return &e.Header }
func (e *NetEvent) GetHeader() *EventHeader    { return &e.Header }
func (e *FileEvent) GetHeader() *EventHeader   { return &e.Header }
func (e *ModuleEvent) GetHeader() *EventHeader { return &e.Header }
func (e *CredEvent) GetHeader() *EventHeader   { return &e.Header }
func (e *DNSEvent) GetHeader() *EventHeader    { return &e.Header }

// ParseEvent parses raw bytes into the appropriate event type.
func ParseEvent(data []byte) (Event, error) {
	if len(data) < 8 {
		return nil, fmt.Errorf("data too short: %d bytes", len(data))
	}

	// Read event ID from header (offset 8, after timestamp)
	eventID := binary.LittleEndian.Uint32(data[8:12])

	var event Event
	var err error

	switch eventID {
	case EventIDExecve:
		e := &ExecveEvent{}
		err = binary.Read(bytes.NewReader(data), binary.LittleEndian, e)
		event = e
	case EventIDExit, EventIDExitGroup:
		e := &ExitEvent{}
		err = binary.Read(bytes.NewReader(data), binary.LittleEndian, e)
		event = e
	case EventIDConnect, EventIDAccept, EventIDBind:
		e := &NetEvent{}
		err = binary.Read(bytes.NewReader(data), binary.LittleEndian, e)
		event = e
	case EventIDOpen, EventIDRename, EventIDLink, EventIDUnlink, EventIDRmdir,
		EventIDMount, EventIDMprotect, EventIDKill, EventIDKillTkill,
		EventIDPtrace, EventIDPrctl, EventIDMemfdCreate, EventIDUsermodehelper,
		EventIDSetsid, EventIDWrite, EventIDCreateFile, EventIDChmod:
		e := &FileEvent{}
		err = binary.Read(bytes.NewReader(data), binary.LittleEndian, e)
		event = e
	case EventIDModuleLoad:
		e := &ModuleEvent{}
		err = binary.Read(bytes.NewReader(data), binary.LittleEndian, e)
		event = e
	case EventIDUpdateCred:
		e := &CredEvent{}
		err = binary.Read(bytes.NewReader(data), binary.LittleEndian, e)
		event = e
	case EventIDDNS:
		e := &DNSEvent{}
		err = binary.Read(bytes.NewReader(data), binary.LittleEndian, e)
		event = e
	default:
		return nil, fmt.Errorf("unknown event ID: %d", eventID)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse event %d: %w", eventID, err)
	}

	return event, nil
}

// cStringToGo converts a null-terminated C string to Go string.
func cStringToGo(b []byte) string {
	n := bytes.IndexByte(b, 0)
	if n == -1 {
		return string(b)
	}
	return string(b[:n])
}

// EventName returns the human-readable name for an event ID.
func EventName(id uint32) string {
	names := map[uint32]string{
		EventIDOpen:           "open",
		EventIDMprotect:       "mprotect",
		EventIDConnect:        "connect",
		EventIDAccept:         "accept",
		EventIDBind:           "bind",
		EventIDExecve:         "execve",
		EventIDExit:           "exit",
		EventIDKill:           "kill",
		EventIDRename:         "rename",
		EventIDLink:           "link",
		EventIDPtrace:         "ptrace",
		EventIDPrctl:          "prctl",
		EventIDSetsid:         "setsid",
		EventIDMount:          "mount",
		EventIDKillTkill:      "tkill",
		EventIDExitGroup:      "exit_group",
		EventIDMemfdCreate:    "memfd_create",
		EventIDDNS:            "dns",
		EventIDCreateFile:     "create_file",
		EventIDModuleLoad:     "module_load",
		EventIDUpdateCred:     "update_cred",
		EventIDRmdir:          "rmdir",
		EventIDUnlink:         "unlink",
		EventIDUsermodehelper: "usermodehelper",
		EventIDWrite:          "write",
		EventIDChmod:          "chmod",
	}
	if name, ok := names[id]; ok {
		return name
	}
	return fmt.Sprintf("unknown_%d", id)
}
