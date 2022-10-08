module github.com/cnbailian/example-logs

go 1.18

require (
	github.com/cnbailian/example v0.0.0
	github.com/cnbailian/heimdallr v0.0.0
)

require (
	github.com/cilium/ebpf v0.9.3 // indirect
	golang.org/x/sys v0.0.0-20220928140112-f11e5e49a4ec // indirect
)

replace (
	github.com/cnbailian/example => ../example/
	github.com/cnbailian/heimdallr => ../../
)
