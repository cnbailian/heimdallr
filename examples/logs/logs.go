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

package main

import (
	"fmt"
	"log"

	"github.com/cnbailian/example/pkg/str"
	"github.com/cnbailian/heimdallr"
)

func main() {
	heimdallr.SetExecutable("../example/example")
	uprobeErrors := heimdallr.Uprobe(str.IntToStr, func() {
		log.Println("call Uprobe func")
	})
	go func() {
		for err := range uprobeErrors {
			log.Println(fmt.Errorf("uprobe error: %w", err))
		}
	}()

	uretprobeErrors := heimdallr.Uretprobe(str.IntToStr, func() {
		log.Println("call Uretprobe func")
	})
	go func() {
		for err := range uretprobeErrors {
			log.Println(fmt.Errorf("uretprobe error: %w", err))
		}
	}()

	select {}
}
