//go:build linux
// +build linux

/*
Copyright 2022 BaiLian.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package heimdallr

import (
	"errors"
	"fmt"
	"os"
	"reflect"
	"runtime"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
)

var executable string

func init() {
	path, _ := os.Executable()
	executable = path
}

func SetExecutable(path string) {
	executable = path
}

type Callback func()

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target native -type event bpf heimdallr.c -- -I./headers

func Uprobe(i interface{}, callback Callback) chan error {
	cherrors := make(chan error)
	go func() {
		if err := uprobe(i, callback, cherrors, false); err != nil {
			cherrors <- err
		}
	}()
	return cherrors
}
func Uretprobe(i interface{}, callback Callback) chan error {
	cherrors := make(chan error)
	go func() {
		if err := uprobe(i, callback, cherrors, true); err != nil {
			cherrors <- err
			close(cherrors)
		}
	}()
	return cherrors
}

func uprobe(i interface{}, callback Callback, cherrors chan error, ret bool) error {
	fn := getFunctionName(i, cherrors)
	if fn == "" {
		return fmt.Errorf("unable to get function: %s", i)
	}

	objs := bpfObjects{}
	if err := loadBpfObjects(&objs, nil); err != nil {
		return fmt.Errorf("loading objects: %w", err)
	}
	defer objs.Close()

	// Open an ELF binary and read its symbols.
	ex, err := link.OpenExecutable(executable)
	if err != nil {
		return fmt.Errorf("opening executable: %w", err)
	}

	if ret {
		up, err := ex.Uretprobe(fn, objs.UprobeCallback, nil)
		if err != nil {
			return fmt.Errorf("creating uprobe: %w", err)
		}
		defer up.Close()
	} else {
		up, err := ex.Uprobe(fn, objs.UprobeCallback, nil)
		if err != nil {
			return fmt.Errorf("creating uretprobe: %w", err)
		}
		defer up.Close()
	}

	rd, err := perf.NewReader(objs.Events, os.Getpagesize())
	if err != nil {
		return fmt.Errorf("creating perf event reader: %w", err)
	}
	defer rd.Close()
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			cherrors <- fmt.Errorf("reading from perf event reader: %w", err)
			continue
		}
		if record.LostSamples != 0 {
			cherrors <- fmt.Errorf("perf event ring buffer full, dropped %d samples", record.LostSamples)
			continue
		}
		callback()
	}
}

func getFunctionName(i interface{}, cherrors chan error) string {
	defer func() {
		if r := recover(); r != nil {
			cherrors <- fmt.Errorf("reflect panic: %s", r)
		}
	}()
	return runtime.FuncForPC(reflect.ValueOf(i).Pointer()).Name()
}
