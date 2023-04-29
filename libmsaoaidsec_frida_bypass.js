function hook_dlopen(soName = '') {
    Interceptor.attach(Module.findExportByName(null, "dlopen"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    // console.log("load " + path);
                    if (path.indexOf(soName) >= 0) {
                        // Thread.sleep(20)
                        locate_init()
                        // hook_libc()
                    }
                }
            }
        }
    );

    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    // console.log("load " + path);
                    if (path.indexOf(soName) >= 0) {
                        // Thread.sleep(20)
                        locate_init()
                        // hook_libc()
                    }
                }
            }
        }
    );
}

function locate_init() {
    let secmodule = null
    Interceptor.attach(Module.findExportByName(null, "__system_property_get"),
        {
            // _system_property_get("ro.build.version.sdk", v1);
            onEnter: function (args) {
                secmodule = Process.findModuleByName("libmsaoaidsec.so")
                var name = args[0];
                if (name !== undefined && name != null) {
                    name = ptr(name).readCString();
                    if (name.indexOf("ro.build.version.sdk") >= 0) {
                        // 这是.init_proc刚开始执行的地方，是一个比较早的时机点
                        hook_so()
                    }
                }
            }
        }
    );
}

function detect() {
    let secmodule = Process.findModuleByName("libmsaoaidsec.so")
    Interceptor.attach(secmodule.base.add(0xC63A + 0x1), {
        onEnter(args) {
            console.log("pc: " + ptr(this.context.pc).sub(secmodule.base))
        }
    })
}

function hook_so() {
    // detect()
    console.log("libmsaoaidsec.so --- " + Process.findModuleByName("libmsaoaidsec.so").base)
    bypass()
}

function hook_libc(){
    // Interceptor.attach(Module.findExportByName(null, "openat"),
    //     {
    //         onEnter: function (args) {
    //             var name = args[1];
    //             if (name !== undefined && name != null) {
    //                 name = ptr(name).readCString();
    //                 console.log("openat --> " + name)
    //                 // if (name.indexOf("ro.build.version.sdk") >= 0) {
                        
    //                 // }
    //             }
    //         }
    //     }
    // );

    // Interceptor.attach(Module.findExportByName(null, "open"),
    //     {
    //         onEnter: function (args) {
    //             var name = args[0];
    //             if (name !== undefined && name != null) {
    //                 name = ptr(name).readCString();
    //                 console.log("open --> " + name)
    //                 // if (name.indexOf("ro.build.version.sdk") >= 0) {
                        
    //                 // }
    //             }
    //         }
    //     }
    // );

    // Interceptor.attach(Module.findExportByName(null, "readlinkat"),
    //     {
    //         onEnter: function (args) {
    //             var name = args[1];
    //             if (name !== undefined && name != null) {
    //                 name = ptr(name).readCString();
    //                 console.log("readlinkat --> " + name)
    //                 // if (name.indexOf("ro.build.version.sdk") >= 0) {
                        
    //                 // }
    //             }
    //         }
    //     }
    // );

    // Interceptor.attach(Module.findExportByName(null, "strstr"),
    //     {
    //         onEnter: function (args) {
    //             var arg0 = args[0];
    //             var arg1 = args[1]
    //             if (arg0 !== undefined && arg0 != null) {
    //                 arg0 = ptr(arg0).readCString();
    //                 arg1 = ptr(arg1).readCString();
    //                 console.log("strstr --> " + arg0  + " --- " + arg1)
    //             }
    //         }
    //     }
    // );

    // Interceptor.attach(Module.findExportByName(null, "sprintf"),
    //     {
    //         onEnter: function (args) {
    //             this.arg0 = args[0]
    //         },onLeave(retval){
    //             let str = ptr(this.arg0).readCString();
    //             console.log("sprintf --> " + str)
    //         }
    //     }
    // );

    // Interceptor.attach(Module.findExportByName(null, "snprintf"),
    //     {
    //         onEnter: function (args) {
    //             this.arg0 = args[0]
    //         },onLeave(retval){
    //             let str = ptr(this.arg0).readCString();
    //             console.log("snprintf --> " + str)
    //         }
    //     }
    // );

    Interceptor.attach(Module.findExportByName("libc.so", "pthread_create"),{
        onEnter(args){
            let func_addr = args[2]
            console.log("The thread function address is " + func_addr)
            // console.log('pthread_create called from:\n' + Thread.backtrace(this.context, Backtracer.ACCURATE).map(DebugSymbol.fromAddress).join('\n') + '\n');
        }
    })
}

function nop(addr) {
    Memory.patchCode(ptr(addr), 4, code => {
        const cw = new ThumbWriter(code, { pc: ptr(addr) });
        cw.putNop();
        cw.putNop();
        cw.flush();
    });
}

function bypass(){
    let module = Process.findModuleByName("libmsaoaidsec.so")
    nop(module.base.add(0x10AE4))
    nop(module.base.add(0x113F8))
}

function main() {
    hook_dlopen("libmsaoaidsec.so")
}

setImmediate(main)
