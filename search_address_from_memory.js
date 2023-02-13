// pattern example '00 00 00 00 ?? 13 37 ?? 42'
function search_address_from_memory(module_name, pattern) {
    let m = Process.findModuleByName(module_name)
    const results = Memory.scanSync(m.base, m.size, pattern)
    if(results.length == 1){
        return results[0]['address'];
    }
    else if(results.length > 1){
        console.log("search_address_from_memory results more than one!!!")
        return 0;
    }
    else{
        console.log("don't find the pattern in memory!!!")
        return 0;
    }
}
