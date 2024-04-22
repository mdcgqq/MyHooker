var offset = -1
//这个函数是用来做偏移矫正的
function get_android_api_jnioffset() {
 
    if(offset != -1){
        return offset
    }
    var native_addr = Module.findExportByName("libandroid_runtime.so", "_Z32android_os_Process_getUidForNameP7_JNIEnvP8_jobjectP8_jstring")
    // console.log("native_addr:",native_addr)
    var className = "android.os.Process";
    var classResult = Java.use(className).class;
    var methodArr = classResult.getDeclaredMethods();
    for (var i = 0; i < methodArr.length; i++) {
 
        var methodName = methodArr[i].toString();
        var flags = methodArr[i].getModifiers()
        if (flags & 256) {
            if(methodName.indexOf("getUidForName")!= -1){
                var artmethod = methodArr[i].getArtMethod();
                for (var i = 0; i < 30; i=i+1) {
                    var jni_native_addr = Memory.readPointer(ptr(artmethod + i))
                    if(native_addr.equals(jni_native_addr)){
                        offset = i
                        return i
                    }
                }
            }
        }
    }
 
    return -1
}
// 遍历一个类的所有native 方法并打印地址
function get_jni_native_method_addr(classResult) {
     
    var jnioffset = get_android_api_jnioffset()
    var methodArr = classResult.getDeclaredMethods();
 
    for (var i = 0; i < methodArr.length; i++) {
 
        var methodName = methodArr[i].toString();
 
        var flags = methodArr[i].getModifiers()
        if (flags & 256) {
            var artmethod = methodArr[i].getArtMethod();
            var native_addr = Memory.readPointer(ptr(artmethod + jnioffset))
            //找到本手机系统中artmethod的偏移地址，然后用20+偏移
            var module
            var offset
            console.log("methodName->", methodName);
            try {
                module = Process.getModuleByAddress(native_addr)
                offset = native_addr - module.base
                console.log("Func.offset==", module.name, offset);
            } catch (err) {
            }
            console.log("Func.getArtMethod->native_addr:", native_addr); //打印出java方法jni函数调用的native函数地址
            console.log("Func.flags->", flags);
        }
 
    }
}
