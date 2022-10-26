# Heimdallr

可对正在运行中的 Go 项目进行追踪调试，项目基于 eBPF Uprobe 的能力，目前由于功能未完善，仅限测试使用
*需要追踪的目标使用禁止内联模式编译*

## 实现

通过 eBPF uprobe 能力实现运行时 go 函数 hook，使用 event map 进行通知

## 使用

### 编译 ebpf 程序

```shell
CLANG=clang-14 make generate
```

### 示例

追踪正在运行中的函数调用，并能够通过 callback 函数动态获得参数

```shell
# 启动正常运行的 Go 程序
$ cd examples/args
$ go build -gcflags="-l"
$ ./args
```

```shell
# 启动追踪程序
$ cd examples/logs
$ go run .
```

```shell
# 通过访问正常运行程序的 http 接口，动态传入参数
$ curl 127.0.0.1:8081/print?str=test
```

## 待实现
1. 根据 go 语言函数调用规约，确认函数参数与响应的传递位置，并通过 eBPF 程序 event map 进行传值
   1. 已根据函数调用规约的位置，实现了函数参数的传输，但还未实现自动解析函数参数位置
   2. 在 eBPF 程序中能够解析参数类型
   3. 或是在 go 程序中根据参数自动生成相应 eBPF 程序
2. 在作为包调用的情况下，使用者该如何生成相应环境的 bpf.o 程序
3. 参考 [monkey patching](https://github.com/bouk/monkey) 实现可 patching 的 aop 函数
   1. 或是能够通过 bpf_probe_write_user 动态修改函数

