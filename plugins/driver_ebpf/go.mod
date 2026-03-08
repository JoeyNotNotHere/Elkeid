module driver_ebpf

go 1.21

require (
	github.com/cilium/ebpf v0.12.3
	plugins v0.0.0
)

require (
	github.com/gogo/protobuf v1.3.2 // indirect
	golang.org/x/exp v0.0.0-20231127185646-65229373498e // indirect
	golang.org/x/sys v0.15.0 // indirect
)

replace plugins => ../lib/go
