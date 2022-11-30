// 使用frida Stalker进行code trace
// 此脚本只对STR、STRB和STRH指令进行trace，用于监听对内存的写入，有需要的话可自行扩展其它指令
let moduleBase;
let isFirstIn = true;
let pre_regs;
let infoMap = new Map();
let detailInsMap = new Map();

function isStrInstuction(logInfo) {
    //13c78           strb w11, [x10, x9]
    let re = /str.*([wx].*?),.*\[(x\d+),\s([wx]\d+)\]/
    let re_ret = logInfo.match(re)
    if (re_ret != null) {
        return re_ret
    }
    //146dc		strb w8, [x9, #3] ; 
    re = /str.*([wx].*?),.*\[(x\d+).*/
    re_ret = logInfo.match(re)
    if (re_ret != null) {
        return re_ret
    }
    return null;
}

let strace = {
    start: function (soname, addr, size) {
        let module = Process.findModuleByName(soname);
        moduleBase = module.base;
        console.log(JSON.stringify(module));

        Interceptor.attach(moduleBase.add(addr), {
            onEnter: function (args) {
                this.pid = Process.getCurrentThreadId();
                //看下结构体的值

                Stalker.follow(this.pid, {
                    transform: function (iterator) {
                        let lastInfo;
                        const instruction = iterator.next();
                        let startAddress = instruction.address;
                        // console.log("startAddress:" + startAddress + " base:" + module.base + " offset:" + offset);
                        if (size === 0) {
                            size = module.size;
                            addr = 0;
                        }
                        const isModuleCode = startAddress.compare(moduleBase.add(addr)) >= 0 &&
                            startAddress.compare(moduleBase.add(addr).add(size)) < 0;
                        // const isModuleCode = startAddress.compare(moduleBase) >= 0 &&
                        //     startAddress.compare(moduleBase.add(module.size)) < 0;
                        do {
                            if (isModuleCode) {
                                let s = parserNextAddr(instruction);
                                let address = instruction.address;
                                let offset = address - moduleBase;
                                let lastInfo = s.toString(16) + "\t\t" + instruction;
                                detailInsMap.set(offset, JSON.stringify(instruction));
                                infoMap.set(offset, lastInfo);
                                iterator.putCallout(function (context) {
                                    let regs = JSON.stringify(context);
                                    //保存寄存器
                                    pre_regs = formatArm64Regs(context);
                                    let pcReg = getPcReg(pre_regs);
                                    let offset = Number(pcReg) - moduleBase;
                                    let logInfo = infoMap.get(offset);
                                    var isStr_ret = isStrInstuction(logInfo)
                                    if (isStr_ret) {
                                        //146dc		strb w8, [x9, #3] ;
                                        let value_reg = isStr_ret[1];
                                        let addr_reg = isStr_ret[2];
                                        let index_reg = null
                                        if(isStr_ret.length == 4){
                                            index_reg = isStr_ret[3]
                                        }
                                        isStr_ret = null
                                        let value_value = getReg(pre_regs, value_reg)
                                        let addr_value = getReg(pre_regs, addr_reg)
                                        let index_value = null
                                        if(index_reg != null){
                                            index_value = getReg(pre_regs, index_reg)
                                        }
                                        let index_str = ''
                                        if(index_value != null){
                                            index_str = "    " + index_reg + '=' + index_value
                                        }
                                        console.log(logInfo + " ; " + addr_reg + "=" + addr_value + index_str + "    " + value_reg + '=' + value_value)

                                        // 保存到文件中
                                        var f = new File("/data/data/com.kanxue.ollvm5/trace4.txt", "a")
                                        f.write(logInfo + " ; " + addr_reg + "=" + addr_value + index_str + "    " + value_reg + '=' + value_value +"\n")
                                        f.flush()
                                        f.close()
                                    }
                                })
                            }
                            iterator.keep()

                        } while (iterator.next() != null)
                    },

                })
            },
            onLeave: function (ret) {
                // libtprt.saveStringMapTofile();
                Stalker.unfollow(this.pid);
                console.log("ret:" + ret);

            }
        })
    }
}

function parserNextAddr(ins) {
    let s = JSON.stringify(ins);
    let address = ins.address;
    // console.log("address:"+address)
    let offset = address - moduleBase;
    let s1 = (offset).toString(16);
    let entity = {}
    entity.address = offset;
    return s1;
}

const byteToHex = [];

for (let n = 0; n <= 0xff; ++n) {
    const hexOctet = n.toString(16).padStart(2, "0");
    byteToHex.push(hexOctet);
}

function hex(arrayBuffer) {
    const buff = new Uint8Array(arrayBuffer);
    const hexOctets = [];
    for (let i = 0; i < buff.length; ++i)
        hexOctets.push(byteToHex[buff[i]]);
    return hexOctets.join("");
}

function formatArm64Regs(context) {
    let regs = []
    regs.push(context.x0);
    regs.push(context.x1);
    regs.push(context.x2);
    regs.push(context.x3);
    regs.push(context.x4);
    regs.push(context.x5);
    regs.push(context.x6);
    regs.push(context.x7);
    regs.push(context.x8);
    regs.push(context.x9);
    regs.push(context.x10);
    regs.push(context.x11);
    regs.push(context.x12);
    regs.push(context.x13);
    regs.push(context.x14);
    regs.push(context.x15);
    regs.push(context.x16);
    regs.push(context.x17);
    regs.push(context.x18);
    regs.push(context.x19);
    regs.push(context.x20);
    regs.push(context.x21);
    regs.push(context.x22);
    regs.push(context.x23);
    regs.push(context.x24);
    regs.push(context.x25);
    regs.push(context.x26);
    regs.push(context.x27);
    regs.push(context.x28);
    regs.push(context.fp);
    regs.push(context.lr);
    regs.push(context.sp);
    regs.push(context.pc);
    return regs;
}

function getPcReg(regs) {
    return regs[32];
}

function getReg(regs, reg) {
    let map = {
        'x0': 0,
        'x1': 1,
        'x2': 2,
        'x3': 3,
        'x4': 4,
        'x5': 5,
        'x6': 6,
        'x7': 7,
        'x8': 8,
        'x9': 9,
        'x10': 10,
        'x11': 11,
        'x12': 12,
        'x13': 13,
        'x14': 14,
        'x15': 15,
        'x16': 16,
        'x17': 17,
        'x18': 18,
        'x19': 19,
        'x20': 20,
        'x21': 21,
        'x22': 22,
        'x23': 23,
        'x24': 24,
        'x25': 25,
        'x26': 26,
        'x27': 27,
        'x28': 28
    }
    if(reg == 'xzr' || reg == 'wzr'){
        return '0x0'
    }
    reg = reg.replace('w','x')
    let index = map[reg]
    return regs[index]
}

function isRegsChange(context, ins) {
    let currentRegs = formatArm64Regs(context);
    let logInfo = "";
    for (let i = 0; i < 32; i++) {
        if (i === 30) {
            continue
        }
        let preReg = pre_regs[i];
        let currentReg = currentRegs[i];
        if (Number(preReg) !== Number(currentReg)) {
            if (logInfo === "") {
                //尝试读取string
                let changeString = "";

                try {
                    let nativePointer = new NativePointer(currentReg);
                    changeString = nativePointer.readCString();
                } catch (e) {
                    changeString = "";
                }
                if (changeString !== "") {
                    currentReg = currentReg + "   (" + changeString + ")";
                }
                logInfo = "\t " + getRegsString(i) + " = " + preReg + " --> " + currentReg;
            } else {
                logInfo = logInfo + "\t " + getRegsString(i) + " = " + preReg + " --> " + currentReg;
            }
        }
    }
    //打印PC寄存器
    let parse = JSON.parse(ins);
    let mnemonic = parse.mnemonic;//补充str
    if (mnemonic === "str") {
        let strParams = getStrParams(parse, currentRegs);
        logInfo = logInfo + strParams;
    } else if (mnemonic === "cmp") {
        let cmpParams = getCmpParams(parse, currentRegs);
        logInfo = logInfo + cmpParams;
    } else if (mnemonic === "b.gt" || mnemonic === "b.le" || mnemonic === "b.eq" || mnemonic === "b.ne" || mnemonic === "b") {
        // console.log(ins)
        let bgtAddr = getbgtAddr(parse, currentRegs);
        logInfo = logInfo + bgtAddr;
    }
    let entity = {};
    entity.info = logInfo;
    let address = parse.address;
    if (lastAddr === undefined) {

        lastAddr = address;
    } else {
        let number = address - lastAddr;
        if (number === 0x4) {

        } else {
            currentIndex++;

        }
        lastAddr = address;
    }
    pre_regs = currentRegs;
    return entity;
}
let lastAddr = undefined;
let currentIndex = 0;
function getRegsString(index) {
    let reg;
    if (index === 31) {
        reg = "sp"
    } else {
        reg = "x" + index;
    }
    return reg;
}
function getbgtAddr(parser, currentRegs) {
    let bgtAddr = "";
    let operands = parser.operands;
    for (let i = 0; i < operands.length; i++) {
        let operand = operands[i];
        if (operand.type === "imm") {
            let value = operand.value;
            let number = value - moduleBase;
            bgtAddr = "\t block addr:" + number.toString(16);
            break
        }
    }
    return bgtAddr;
}
function getStrParams(parser, currentRegs) {
    let operands = parser.operands;
    for (let i = 0; i < operands.length; i++) {
        let operand = operands[i];
        if (operand.type === "reg") {
            //获取value
            let value = operand.value;
            if (value === "wzr") {
                return "\t " + "str = 0";
            } else {
                let replace = value.replace("w", "");
                let index = replace.replace("x", "");
                let index_reg = currentRegs[index];

                let changeString = "";

                try {
                    let nativePointer = new NativePointer(index_reg);
                    changeString = nativePointer.readCString();
                } catch (e) {
                    changeString = "";
                }
                //读取值
                if (changeString !== "") {
                    index_reg = index_reg + "   (" + changeString + ")";
                }
                return "\t " + "str = " + index_reg;
            }

        }
    }
}
function getCmpParams(parser, currentRegs) {
    let operands = parser.operands;
    let cmpInfo = "";
    for (let i = 0; i < operands.length; i++) {
        let operand = operands[i];
        if (operand.type === "reg") {
            let value = operand.value;
            let replace = value.replace("w", "");
            let index = replace.replace("x", "");
            let index_reg = currentRegs[index];
            let changeString = "";
            try {
                let nativePointer = new NativePointer(index_reg);
                changeString = nativePointer.readCString();
            } catch (e) {
                changeString = "";
            }
            //读取值
            if (changeString !== "") {
                index_reg = index_reg + "   (" + changeString + ")";
            }
            cmpInfo = cmpInfo + "\t " + value + " = " + index_reg;
        }
    }
    return cmpInfo;
}

let once = false;
let straceInject = {
    start: function (soName, offset, size) {
        let module = Process.findModuleByName(soName);
        if (module !== undefined) {
            trace(soName, offset, size)
            return;
        }
        let open = Module.findExportByName(null, "open");
        if (open != null) {
            Interceptor.attach(open, {
                onEnter: function (args) {
                    let path = args[0].readCString();
                    if (path.indexOf(soName) !== -1) {
                        this.hook = true;
                    }
                },
                onLeave: function (ret) {
                    if (this.hook) {
                        trace(soName, offset, size);
                    }
                }
            })
        }
    }
}

function trace(soName, offset, size) {

    let module = Process.findModuleByName(soName);
    console.log("module:" + module)
    if (module === undefined
        || module === null) {
        setTimeout(function () {
            trace(soName, offset, size);
        }, 100);
    }
    console.log("module:" + module.base)
    if (once) {
        return
    }
    once = true;
    strace.start(soName, offset, size);
}

function main() {
    // 模块名 代码偏移 大小 
    /**
     * idapython:
# function
import idaapi

currentFunc = idaapi.get_func(idaapi.get_screen_ea())
funcStart = currentFunc.start_ea
funcEnd = currentFunc.end_ea
print("start:" + str(hex(funcStart)) + ", end:" + str(hex(funcEnd)) + ", size:" + str(hex(funcEnd - funcStart)))
     */
    // 大小为0，表示trace整个模块
    straceInject.start("libnative-lib.so", 0x19A84, 0x0);
}

setImmediate(main)
