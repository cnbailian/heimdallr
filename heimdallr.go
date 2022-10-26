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

import "C"
import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"log"
	"os"
	"reflect"
	"runtime"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/ringbuf"
)

var executable string

func init() {
	path, _ := os.Executable()
	executable = path
}

func SetExecutable(path string) {
	executable = path
}

type Callback interface{}

// $BPF_CLANG and $BPF_CFLAGS are set by the Makefile.
//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc $BPF_CLANG -cflags $BPF_CFLAGS -target native -type endInfo -type goString -type goInt bpf heimdallr.c -- -I./headers

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

	rd, err := ringbuf.NewReader(objs.Events)
	if err != nil {
		log.Fatalf("opening ringbuf reader: %s", err)
	}
	defer rd.Close()

	f := reflect.TypeOf(i)
	var key int
	for i := 0; i < f.NumIn(); i++ {
		aTyp := argTypes[f.In(i).String()]
		if err := objs.Args.Update(uint32(key), aTyp, ebpf.UpdateAny); err != nil {
			log.Fatalf("update args: %s", err)
		}
		if aTyp == STRING {
			key++
		}
		key++
	}

	var res = map[uint32][]interface{}{}
	for {
		record, err := rd.Read()
		if err != nil {
			if errors.Is(err, perf.ErrClosed) {
				return nil
			}
			cherrors <- fmt.Errorf("reading from perf event reader: %w", err)
			continue
		}

		if len(record.RawSample) < 3 {
			cherrors <- fmt.Errorf("parsing ringbuf RawSample: length %d", len(record.RawSample))
			continue
		}

		t := record.RawSample[0]
		switch t {
		case INT:
			var i = bpfGoInt{}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &i); err != nil {
				cherrors <- fmt.Errorf("parsing int event: %s", err)
				continue
			}
			res[i.Rid] = append(res[i.Rid], i)
		case STRING:
			var s = bpfGoString{}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &s); err != nil {
				cherrors <- fmt.Errorf("parsing string event: %s", err)
				continue
			}
			res[s.Rid] = append(res[s.Rid], s)
		case ENDINFO:
			var end = bpfEndInfo{}
			if err := binary.Read(bytes.NewBuffer(record.RawSample), binary.LittleEndian, &end); err != nil {
				cherrors <- fmt.Errorf("parsing endinfo event: %s", err)
				continue
			}

			args := getFunctionArgs(i, res[end.Rid], cherrors)
			f := reflect.ValueOf(callback)
			f.Call(args)
		}
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

func getFunctionArgs(i interface{}, argRaws []interface{}, cherrors chan error) []reflect.Value {
	f := reflect.TypeOf(i)
	numIn := f.NumIn()
	var res []reflect.Value
	for i := 0; i < numIn; i++ {
		if f.In(i).String() == "string" {
			bpfStr := argRaws[i].(bpfGoString)
			if int(bpfStr.Len) > len(bpfStr.S) {
				res = append(res, reflect.ValueOf(string(bpfStr.S[:])))
			} else {
				res = append(res, reflect.ValueOf(string(bpfStr.S[:bpfStr.Len])))
			}
		}
		if f.In(i).String() == "int" {
			intVal := argRaws[i].(bpfGoInt).I
			res = append(res, reflect.ValueOf(int(intVal)))
		}
	}
	return res
}
