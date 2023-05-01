function hook_dlopen(soName = '') {
    Interceptor.attach(Module.findExportByName(null, "android_dlopen_ext"),
        {
            onEnter: function (args) {
                var pathptr = args[0];
                if (pathptr !== undefined && pathptr != null) {
                    var path = ptr(pathptr).readCString();
                    if (path.indexOf(soName) >= 0) {
                        this.is_can_hook = true;
                    }
                }
            },
            onLeave: function (retval) {
                if (this.is_can_hook) {
                    // do something
                    crack()
                    hook_libc()
                }
            }
        }
    );
}

function crack() {
    let module = Process.findModuleByName("libluajava.so")
    Interceptor.attach(module.findExportByName("luaL_checklstring"), {
        onEnter(args) {
            this.len = this.context.r2
        },
        onLeave(retval) {
            let src = ptr(retval).readCString()
            let md52 = null
            // console.log(src)
            if (src.indexOf("卡密不存在") >= 0) {
                // src = JSON.parse(src)
                // console.log(src["wb569a04a9d5a36d0d01"])
                let time = Math.floor(Date.now() / 1000)
                let str = String.raw`{"wb569a04a9d5a36d0d01":42900409,"w893c8f0e02a09b1d456":{"w4f7c661779204e7a5bb698af870a702b":"5519a2cdbae6ec53e0fe6a932d6ebb2c","wc67ecedeb18e0870203":2105380,"wb20f98c65058d838c15":"code","w150c99a51e259947af9":1717046228},"wb6bf85eefb5573bd940":${time},"wc2e86b326e09409e0fd":"dd9199d043971e5c4d7e4cf184efdc25","w295f80348b106b9c15c":"f50a7dadcc9830250affcddb09e75d03"}`
                ptr(this.len).writeInt(374)
                ptr(this.context.r0).writeUtf8String(str)
                console.log(ptr(retval).readCString())
            }
        }
    })
}

function hook_libc() {
  // lua字符串比较
    Interceptor.attach(Module.getExportByName(null, "memcmp"), {
        onEnter(args) {
            let str1 = ptr(this.context.r0).readCString()
            let str2 = ptr(this.context.r0).readCString()
            if (str1.indexOf("dd9199d043971e5c4d7e4cf184efdc25") >= 0 || str2.indexOf("dd9199d043971e5c4d7e4cf184efdc25") >= 0) {
                console.log(str1 + "---" + str2)
            }
        }
    })
}

function main() {
    hook_dlopen("libluajava.so")
}

setImmediate(main)
