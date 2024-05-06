import ida_dbg

current_tid = ida_dbg.get_current_thread()
for number in range(ida_dbg.get_thread_qty()):
    tid = ida_dbg.getn_thread(number)
    if (tid != current_tid):
        ida_dbg.suspend_thread(tid)
