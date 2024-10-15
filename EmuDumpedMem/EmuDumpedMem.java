import com.alibaba.fastjson.JSONArray;
import com.alibaba.fastjson.JSONObject;
import com.github.unidbg.AndroidEmulator;
import com.github.unidbg.arm.backend.Backend;
import com.github.unidbg.arm.backend.Unicorn2Factory;
import com.github.unidbg.linux.android.AndroidEmulatorBuilder;
import com.github.unidbg.linux.android.AndroidResolver;
import com.github.unidbg.linux.android.dvm.AbstractJni;
import com.github.unidbg.linux.android.dvm.*;
import com.github.unidbg.memory.Memory;
import com.github.unidbg.Module;
import org.apache.commons.io.IOUtils;
import unicorn.Arm64Const;
import unicorn.ArmConst;
import unicorn.UnicornConst;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Arrays;
import java.util.List;
import java.util.zip.DataFormatException;
import java.util.zip.Inflater;

public class EmuDumpedMem extends AbstractJni {
    private final AndroidEmulator emulator;
    private final VM vm;
    final Memory memory;
    final Backend backend;
    int UNICORN_PAGE_SIZE = 0x1000;

    EmuDumpedMem() {
        emulator = AndroidEmulatorBuilder.for64Bit()
                .setProcessName("process_name")
                .addBackendFactory(new Unicorn2Factory(true))
                .build();
        memory = emulator.getMemory();
        memory.setLibraryResolver(new AndroidResolver(23));

        vm = emulator.createDalvikVM();
        backend = emulator.getBackend();
        vm.setJni(this);
        vm.setVerbose(true);
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
        backend.reg_write(Arm64Const.UC_ARM64_REG_TPIDR_EL0, 0x6ed6378000L); // MRS 指令执行后第一个寄存器的值

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

            List<String> white_list = Arrays.asList(new String[]{"libneeded.so", "libc.so", "[anon:stack_and_tls:13240]", "[anon:.bss]"});
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

    private void call_func() {
        // 需要将 maxLengthLibraryName = memory.getMaxLengthLibraryName().length(); 改为 maxLengthLibraryName = 32;
        emulator.traceCode();
        long ctx_addr = backend.reg_read(Arm64Const.UC_ARM64_REG_PC).longValue();
        Number result = Module.emulateFunction(emulator, ctx_addr);
    }

    public static void main(String[] args) throws Exception {
        EmuDumpedMem emuDumpedMem = new EmuDumpedMem();
        emuDumpedMem.load_context("your/dump/path");
        emuDumpedMem.call_func();
    }
}
