function set_exceprion_break(addr, size, pattern) {
    Process.setExceptionHandler(function(details) {
        console.log(`type:${details.type} addr:${details.address} memory:${details.memory.address.toString()}:${details.memory.operation}`)
        Memory.protect(addr, size, 'rwx')
        return true;
    })
    Memory.protect(addr, size, pattern)
}

// 监听写入操作
// set_exceprion_break(ptr(this.context.x0), 8, "rx")
