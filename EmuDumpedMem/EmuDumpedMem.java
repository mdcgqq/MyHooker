package xxxxxx;

import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.Module;
import com.github.unidbg.arm.backend.*;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.memory.MemoryBlock;
import com.github.unidbg.pointer.UnidbgPointer;
import com.github.unidbg.utils.Inspector;
import org.apache.commons.io.IOUtils;
import org.apache.log4j.Level;
import org.apache.log4j.Logger;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.UnicornConst;

import java.io.*;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

public class EmuDumpedMem extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    final Memory memory;
    final Backend backend;
    int UNICORN_PAGE_SIZE = 0x1000;
    // 创建一个全局的ConcurrentHashMap来存储内存块的指针和大小
    ConcurrentHashMap<Integer, Integer> memoryMap = new ConcurrentHashMap<>();

    EmuDumpedMem() {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("com.ss.android.ugc.aweme")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        vm = emulator.createDalvikVM();
        backend = emulator.getBackend();
        vm.setJni(this);
        vm.setVerbose(true);
        Logger.getRootLogger().setLevel(Level.ALL);
    }

    private long align_page_down(long x){
        return x & ~(UNICORN_PAGE_SIZE - 1);
    }
    private long align_page_up(long x){
        return (x + UNICORN_PAGE_SIZE - 1) & ~(UNICORN_PAGE_SIZE - 1);
    }
    private void map_segment(long address, long size, int perms){

        long mem_start = address;
        long mem_end = address + size;
        long mem_start_aligned = align_page_down(mem_start);
        long mem_end_aligned = align_page_up(mem_end);

        if (mem_start_aligned < mem_end_aligned){
            emulator.getBackend().mem_map(mem_start_aligned, mem_end_aligned - mem_start_aligned, perms);
        }
    }

    private void load_context(String dump_dir) throws IOException, DataFormatException, IOException {
        backend.reg_write(Arm64Const.UC_ARM64_REG_CPACR_EL1, 0x300000L);
        backend.reg_write(Arm64Const.UC_ARM64_REG_TPIDR_EL0, 0x6ed66cf000L); // MRS 指令执行后第一个寄存器的值

        String context_file = dump_dir + "/" + "memory_dump.json";
        InputStream is = new FileInputStream(context_file);
        String jsonTxt = IOUtils.toString(is, "UTF-8");
        JSONObject context = JSONObject.parseObject(jsonTxt);
        JSONObject regs = context.getJSONObject("registers");

        backend.reg_write(Arm64Const.UC_ARM64_REG_X0, Long.parseUnsignedLong(regs.getString("x0").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X1, Long.parseUnsignedLong(regs.getString("x1").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X2, Long.parseUnsignedLong(regs.getString("x2").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X3, Long.parseUnsignedLong(regs.getString("x3").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X4, Long.parseUnsignedLong(regs.getString("x4").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X5, Long.parseUnsignedLong(regs.getString("x5").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X6, Long.parseUnsignedLong(regs.getString("x6").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X7, Long.parseUnsignedLong(regs.getString("x7").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X8, Long.parseUnsignedLong(regs.getString("x8").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X9, Long.parseUnsignedLong(regs.getString("x9").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X10, Long.parseUnsignedLong(regs.getString("x10").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X11, Long.parseUnsignedLong(regs.getString("x11").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X12, Long.parseUnsignedLong(regs.getString("x12").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X13, Long.parseUnsignedLong(regs.getString("x13").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X14, Long.parseUnsignedLong(regs.getString("x14").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X15, Long.parseUnsignedLong(regs.getString("x15").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X16, Long.parseUnsignedLong(regs.getString("x16").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X17, Long.parseUnsignedLong(regs.getString("x17").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X18, Long.parseUnsignedLong(regs.getString("x18").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X19, Long.parseUnsignedLong(regs.getString("x19").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X20, Long.parseUnsignedLong(regs.getString("x20").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X21, Long.parseUnsignedLong(regs.getString("x21").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X22, Long.parseUnsignedLong(regs.getString("x22").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X23, Long.parseUnsignedLong(regs.getString("x23").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X24, Long.parseUnsignedLong(regs.getString("x24").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X25, Long.parseUnsignedLong(regs.getString("x25").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X26, Long.parseUnsignedLong(regs.getString("x26").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X27, Long.parseUnsignedLong(regs.getString("x27").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_X28, Long.parseUnsignedLong(regs.getString("x28").substring(2), 16));

        backend.reg_write(Arm64Const.UC_ARM64_REG_FP, Long.parseUnsignedLong(regs.getString("fp").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_LR, Long.parseUnsignedLong(regs.getString("lr").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_SP, Long.parseUnsignedLong(regs.getString("sp").substring(2), 16));
        backend.reg_write(Arm64Const.UC_ARM64_REG_PC, Long.parseUnsignedLong(regs.getString("pc").substring(2), 16));
        backend.reg_write(ArmConst.UC_ARM_REG_CPSR, Long.parseUnsignedLong(regs.getString("cpsr").substring(2), 16));


        JSONArray segments = context.getJSONArray("segments");
        for (int i = 0; i < segments.size(); i++) {
            JSONObject segment = segments.getJSONObject(i);
            String path = segment.getString("name");
            long start = segment.getLong("start");
            long end = segment.getLong("end");
            String content_file = segment.getString("content_file");
            JSONObject permissions = segment.getJSONObject("permissions");
            int perms = 0;
            if (permissions.getBoolean("r")){
                perms |= UnicornConst.UC_PROT_READ;
            }
            if (permissions.getBoolean("w")){
                perms |= UnicornConst.UC_PROT_WRITE;
            }
            if (permissions.getBoolean("x")){
                perms |= UnicornConst.UC_PROT_EXEC;
            }

            String[] paths = path.split("/");
            String module_name = paths[paths.length - 1];

            List<String> white_list = Arrays.asList(new String[]{"libxxxxx.so", "libc.so", "[anon:stack_and_tls:19943]", "[anon:scudo:primary]", "[anon:.bss]"});
            if (white_list.contains(module_name)){
                int size = (int)(end - start);

                map_segment(start, size, perms);
                String content_file_path = dump_dir + "/" + content_file;

                File content_file_f = new File(content_file_path);
                if (content_file_f.exists()){
                    InputStream content_file_is = new FileInputStream(content_file_path);
                    byte[] content_file_buf = IOUtils.toByteArray(content_file_is);

                    // zlib解压
                    Inflater decompresser = new Inflater();
                    decompresser.setInput(content_file_buf, 0, content_file_buf.length);
                    byte[] result = new byte[size];
                    int resultLength = decompresser.inflate(result);
                    decompresser.end();

                    backend.mem_write(start, result);
                }
                else {
                    System.out.println("not exists path=" + path);
                    byte[] fill_mem = new byte[size];
                    Arrays.fill( fill_mem, (byte) 0 );
                    backend.mem_write(start, fill_mem);
                }

            }
        }
    }

    private void impl_func() {
        backend.hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                long module_base = 0x6ed94e4458L - 0x66458L;
                // 解决三方 so 调用错误
                // call libc.so free
                if (address == module_base + 0x2FAE0) {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue());
                    // 从map中去掉
                    int ptr = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
                    memoryMap.remove(ptr);
                }
                // call libc.so malloc
                if (address == module_base + 0x2FB80) {
                    int msize = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
                    MemoryBlock block = emulator.getMemory().malloc(msize, true);
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, block.getPointer().toIntPeer());
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue());
                    // 将分配的内存块的指针和大小存入map中
                    memoryMap.put(block.getPointer().toIntPeer(), msize);
                }
                // call libc.so realloc
                if (address == module_base + 0x2FD80) {
                    // 获取realloc的参数：ptr和new_size
                    long ptrAddress = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                    int newSize = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();

                    // 获取原始内存块的大小（这里假设你知道如何获取原始大小，或者你有其他方式来管理内存）
                    int originalSize = memoryMap.getOrDefault((int)ptrAddress, 1024);

                    // 如果新大小大于原始大小，扩展内存块
                    if (newSize > originalSize) {
                        // 分配新的内存块
                        MemoryBlock newBlock = emulator.getMemory().malloc(newSize, true);
                        // 复制原始数据到新块
                        byte[] buffer = new byte[originalSize];
                        UnidbgPointer.pointer(emulator, ptrAddress).read(0, buffer, 0, originalSize);
                        newBlock.getPointer().write(0, buffer, 0, originalSize);
                        // 释放原始内存块
                        memoryMap.remove((int)ptrAddress);
                        // 将分配的内存块的指针和大小存入map中
                        memoryMap.put(newBlock.getPointer().toIntPeer(), newSize);
                        // 更新指针
                        backend.reg_write(Arm64Const.UC_ARM64_REG_X0, newBlock.getPointer().toUIntPeer());
                    } else {
                        // 如果新大小小于或等于原始大小，我们只是返回原始指针
                        backend.reg_write(Arm64Const.UC_ARM64_REG_X0, ptrAddress);
                    }

                    // 使程序跳转到lr寄存器，继续执行
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue());
                }
                // call libc.so strndup
                if (address == module_base + 0x30170) {
                    // 获取strndup的参数：src字符串和最大长度n
                    UnidbgPointer srcPointer = emulator.getContext().getPointerArg(0);
                    int n = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();

                    // 读取src字符串的前n个字节
                    byte[] bytes = new byte[n];
                    srcPointer.read(0, bytes, 0, n);

                    // 找到字符串的实际结尾，因为C字符串以null字节结尾
                    int actualLength = 0;
                    for (; actualLength < n; actualLength++) {
                        if (bytes[actualLength] == 0) {
                            break;
                        }
                    }

                    // 分配新的内存块来存储复制的字符串，并把字符串复制进去
                    MemoryBlock block = emulator.getMemory().malloc(actualLength + 1, true);
                    block.getPointer().write(0, bytes, 0, actualLength);
                    // 确保字符串以null字节结尾
                    backend.mem_write(block.getPointer().toIntPeer() + actualLength, new byte[]{0});

                    // 返回新分配的内存块的地址
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, block.getPointer().toUIntPeer());

                    // 将分配的内存块的指针和大小存入map中
                    memoryMap.put(block.getPointer().toIntPeer(), actualLength + 1);

                    Inspector.inspect("[strndup]addr:0x" + Integer.toHexString(block.getPointer().toIntPeer()), bytes, actualLength + 1);

                    // 使程序跳转到lr寄存器，继续执行
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue());
                }
                // call libc.so gettimeofday
                if (address == module_base + 0x2F8B0) {
                    UnidbgPointer tv_ptr = emulator.getContext().getPointerArg(0);
                    ByteBuffer tv = ByteBuffer.allocate(8);
                    tv.order(ByteOrder.LITTLE_ENDIAN);
                    long timestamp = System.currentTimeMillis();
                    tv.putLong(timestamp);
                    byte[] data = tv.array();
                    tv_ptr.write(0,data,0,8);
                    System.out.println("[gettimeofday] time:" + timestamp);
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue());
                }
                // call libc.so _cxa_atexit
                if (address == module_base + 0x301C0) {
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue());
                }

                // call libc.so pthread_once
                if (address == module_base + 0x2FC60) {
                    int ONCE_INITIALIZATION_NOT_YET_STARTED = 0;
                    int ONCE_INITIALIZATION_UNDERWAY = 1;
                    int ONCE_INITIALIZATION_COMPLETE = 2;
                    long once_control_ptr = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                    UnidbgPointer uni_once_control_ptr = UnidbgPointer.pointer(emulator, once_control_ptr);
                    int old_value = uni_once_control_ptr.getInt(0);
                    if (old_value == ONCE_INITIALIZATION_COMPLETE) {
                        backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue());
                    } else {
                        System.out.println("请实现 pthread_once 没有初始化的情况。");
                    }
                }

                // call libc.so calloc
                if (address == module_base + 0x2FB50) {
                    // 获取calloc的参数：元素数量和每个元素的大小
                    int num = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).intValue();
                    int msize = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();

                    // 计算总的分配大小
                    int totalSize = num * msize;

                    // 分配内存块，并初始化为零
                    MemoryBlock block = emulator.getMemory().malloc(totalSize, true);
                    block.getPointer().write(0, new byte[totalSize], 0, totalSize);

                    // 将分配的内存块地址放入x0寄存器
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, block.getPointer().toUIntPeer());

                    // 将分配的内存块的指针和大小存入map中
                    memoryMap.put(block.getPointer().toIntPeer(), totalSize);

                    // 跳转到返回地址，继续执行程序
                    backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_LR).longValue());
                }
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, 1, 0, emulator);
    }

    // 有些地址是 0xb4开头，没有完整的内存管理，会报unmap的错误
    private void fix_ptr_addr() {
        backend.hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address == 0x6ed94d4760L) {
                    long addr = backend.reg_read(Arm64Const.UC_ARM64_REG_X0).longValue();
                    addr &= 0xffffffffffL;
                    backend.reg_write(Arm64Const.UC_ARM64_REG_X0, addr);
                }
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, 1, 0, emulator);
    }

    // 由于是dump的内存，所以 jobject 的引用 unidbg 是没有管理的。
    private void fix_jni_ctx() {
        backend.hook_add_new(new CodeHook() {
            @Override
            public void hook(Backend backend, long address, int size, Object user) {
                if (address == 0x6ed95a61e4L) {
                    int jobj_index = backend.reg_read(Arm64Const.UC_ARM64_REG_X1).intValue();
                    if (jobj_index == 0x38c6) {
                        DvmClass AwemeHostApplication = vm.resolveClass("xxxxxxxx", new DvmClass[0]);
                        int index = vm.addGlobalObject(AwemeHostApplication);
                        backend.reg_write(Arm64Const.UC_ARM64_REG_X0, index);
                        System.out.println("[GetObjectClass] xxxxxxxx@0x" + Integer.toHexString(index));
                        // 同时替换掉原先的 jobj
                        DvmObject AwemeHostApplication_obj = AwemeHostApplication.newObject(null);
                        int index2 = vm.addGlobalObject(AwemeHostApplication_obj);
                        backend.reg_write(Arm64Const.UC_ARM64_REG_X22, index2);
                        backend.reg_write(Arm64Const.UC_ARM64_REG_PC, backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue() + 4);
                    }
                }
            }

            @Override
            public void onAttach(UnHook unHook) {

            }

            @Override
            public void detach() {

            }
        }, 1, 0, emulator);
    }

    private void call_func() throws FileNotFoundException {
        // 有一个全局变量是 JavaVM *
        UnidbgPointer jvm = (UnidbgPointer) vm.getJavaVM();
        long module_base = 0x6ed94e4458L - 0x66458L;

        ByteBuffer buffer = ByteBuffer.allocate(8); // 分配8字节的缓冲区
        buffer.order(ByteOrder.LITTLE_ENDIAN); // 设置为小端字节序
        buffer.putLong(jvm.peer); // 将long值写入缓冲区
        byte[] byteArray = buffer.array(); // 获取字节数组

        backend.mem_write(module_base + 0x2877C0, byteArray);

        // 需要将 maxLengthLibraryName = memory.getMaxLengthLibraryName().length(); 改为 maxLengthLibraryName = 32;
//        emulator.traceCode();
        // 需要将 int maxLength = emulator.getMemory().getMaxLengthLibraryName().length(); 改为 maxLength = 16;
//        emulator.attach().addBreakPoint(0x6ed94e460cL);
        long ctx_addr = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        Number result = Module.emulateFunction(emulator, ctx_addr);
    }

    public static void main(String[] args) throws Exception {
        EmuDumpedMem emuDumpedMem = new EmuDumpedMem();
        emuDumpedMem.impl_func();
        emuDumpedMem.fix_ptr_addr();
        emuDumpedMem.fix_jni_ctx();
        emuDumpedMem.load_context("your/dumped/path");
        emuDumpedMem.call_func();
    }
}
