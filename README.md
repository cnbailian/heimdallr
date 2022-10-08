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

追踪正在运行中的 example 项目的函数调用

```shell
$ (cd examples/example && go build -gcflags="-l")
$ cd examples/example
$ go build -o logs
$ ./logs
```

## 待实现
1. 根据 go 语言函数调用规约，确认函数参数与响应的传递位置，并通过 eBPF 程序 event map 进行传值
2. 在包的情况下，使用者该如何生成相应环境的 bpf.o 程序
3. 参考 [monkey patching](https://github.com/bouk/monkey) 实现可 patching 的 aop 函数
4. 或者有什么方式能在外部 patching？这应该很难

