## EmuDumpedMem

该项目结合了内存 dump 和 unidbg 的功能特点，可以在程序运行的某个节点保存内存上下文，然后在 unidbg 中恢复程序执行的上下文，可以解决参数是复杂结构体难以构造的问题。

## 使用

### 1. 内存 dump

可以使用 stackplz 的 uprobe hook + SIGSTOP，让程序在指定的位置中断。

```
./stackplz -n com.ss.android.ugc.aweme -w 0x66454 --lib libmetasec_ml.so --kill SIGSTOP
```

在命令行中使用 kill -SIGCONT {{pid}} 命令恢复程序运行。

使用 lldb 连接手机的 lldb-server，运行 dump 内存的脚本。

```
安卓手机客户端
./lldb-server platform --listen "*:1234" --server

pc客户端
export ANDROID_PLATFORM_LOCAL_PORT=1234
export ANDROID_PLATFORM_LOCAL_GDB_PORT=1234
lldb
(lldb) platform select remote-android
(lldb) platform connect connect://:1234
(lldb) attach {{pid}}
(lldb) t {{tid}}
(lldb) command script import xxxxxx/dump_memory.py
(lldb) dump_memory
(lldb) process detach
```

### 2. Unidbg 加载内存

调用装载内存函数

```
emuDumpedMem.load_context("your/dumped/path");
```

替换 UC_ARM64_REG_TPIDR_EL0 的值，这个需要等 MRS 指令执行后，获取第一个寄存器的值

```
backend.reg_write(Arm64Const.UC_ARM64_REG_TPIDR_EL0, 0x6ed66cf000L); // MRS 指令执行后第一个寄存器的值
```

填写需要加载的内存段，这里最开始先写目标 so 和 libc.so，其他的内存段需要程序运行后报错进行确认。一般在目标 so 的指令执行时，会出现 UNMAP 的错误，如果不是目标 so 的指令出现的错误，一般是因为调用的第三方函数，这时就要手动实现了。

```
List<String> white_list = Arrays.asList(new String[]{"libxxx.so", "libc.so", "[anon:stack_and_tls:19943]", "[anon:scudo:primary]", "[anon:.bss]"});
```

修改 impl_func 函数中的 module_base，计算方法是内存中的第一条指令的地址减去对应的偏移地址。

```
long module_base = 0x6ed94e4458L - 0x66458L;
```

修改 impl_func 函数中的方法偏移，偏移寻找方法是根据方法名称在ida 的 import 中找到对应的函数，然后分局交叉引用找到对应的跳板函数的第一条指令的地址。

```
// call libc.so free
if (address == module_base + 0x2FAE0) {
```

修改或禁用 fix_ptr_addr 函数，因为有些内存的地址类似于0xb400006e875a9c7e，这种 unidbg 执行时会报错，如果没有那么紧用掉 fix_ptr_addr 函数的调用。

```
if (address == 0x6ed94d4760L) {
    long addr = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
    addr &= 0xffffffffffL;
    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, addr);
}
```

修改或禁用 fix_jni_ctx 函数，因为 dump 的内存中 jobject 存放的是一个引用，在 unidbg 模拟执行时是不知道 jobject 引用的具体实例的，所以需要手动修复。

```
if (address == 0x6ed95a61e4L) {
    int jobj_index = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
    if (jobj_index == 0x38c6) {
        DvmClass AwemeHostApplication = vm.resolveClass("com.ss.android.ugc.aweme.app.host.AwemeHostApplication", new DvmClass[0]);
        int index = vm.addGlobalObject(AwemeHostApplication);
        backend.reg_write(Arm64Const.UC_ARM64_REG_X0, index);
        System.out.println("[GetObjectClass] com.xxx.xxx@0x" + Integer.toHexString(index));
        // 同时替换掉原先的 jobj
        DvmObject AwemeHostApplication_obj = AwemeHostApplication.newObject(null);
        int index2 = vm.addGlobalObject(AwemeHostApplication_obj);
        backend.reg_write(Arm64Const.UC_ARM64_REG_X22, index2);
        backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue() + 4);
    }
}
```

最后自己实现 call_func 函数进行模拟执行。

# Ref

本项目参考了以下项目和文章：

[dump内存与模拟执行（二）——编写dump脚本](https://blog.seeflower.dev/archives/166/)
[dump内存与模拟执行（三）——实践dump上下文](https://blog.seeflower.dev/archives/169/)
[dump内存与模拟执行（四）——接入unidbg](https://blog.seeflower.dev/archives/170/)
[dump内存与模拟执行（五）——实战复杂样本](https://blog.seeflower.dev/archives/171/)

