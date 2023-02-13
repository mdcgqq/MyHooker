function dump_so(so_name) {
    var libso = Process.findModuleByName(so_name);
    if (libso == null) {
        return -1;
    }
    Memory.protect(ptr(libso.base), libso.size, 'rwx');
    var libso_buffer = ptr(libso.base).readByteArray(libso.size);
    var f = new File("/data/data/com.mdcg.a360/libjiagu_64.so", "wb") // 更改保存路径
    f.write(libso_buffer)
    f.flush()
    f.close()
    console.log("success dump so, base:" + libso.base)
}
