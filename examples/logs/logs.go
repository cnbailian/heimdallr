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

	"github.com/cnbailian/heimdallr"
	"github.com/cnbailian/heimdallr/utils"
)

func main() {
	heimdallr.SetExecutable("../args/args")
	uprobeErrors := heimdallr.Uprobe(utils.Pppppppppppp, func(x string, y string, t string, c string, o int, q int, w int, r string) {
		log.Printf("call Uprobe func: arg1: %v, arg2: %v, arg3: %v, arg4: %v, arg5: %v, arg6: %v, arg7: %v, arg8: %v", x, y, t, c, o, q, w, r)
	})
	go func() {
		for err := range uprobeErrors {
			log.Println(fmt.Errorf("uprobe error: %w", err))
		}
	}()

	// Uretprobe 如何正确获得函数参数？后者 Uretprobe 不应该进行传参？
	uretprobeErrors := heimdallr.Uretprobe(utils.Pppppppppppp, func(x string, y string, t string, c string, o int, q int, w int, r string) {
		log.Printf("call Uretprobe func: arg1: %v, arg2: %v, arg3: %v, arg4: %v, arg5: %v, arg6: %v, arg7: %v, arg8: %v", x, y, t, c, o, q, w, r)
	})
	go func() {
		for err := range uretprobeErrors {
			log.Println(fmt.Errorf("uretprobe error: %w", err))
		}
	}()

	select {}
}
