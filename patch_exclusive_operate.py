from capstone import *
import re
from keystone import *

exclusive_store_instructions = ["STLXP", "STLXR", "STLXRB", "STLXRH", "STXP", "STXR", "STXRB", "STXRH"]
exclusive_load_instructions = ["LDAXP", "LDAXR", "LDAXRB", "LDAXRH", "LDXP", "LDXR", "LDXRB", "LDXRH"]
exclusive_judge_instructions = ["CBNZ", "CBZ"]

f = open('./libxxx.so', '+rb')
code = f.read()
new_code = bytearray(code)

count = 0

md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
for (address, size, mnemonic, op_str) in md.disasm_lite(code[0x24000:0x167CB5], 0x24000):
	# 检查指令是不是原子存储
	if (mnemonic.upper() in exclusive_store_instructions):
		print("0x%x:\t%s\t%s" %(address, mnemonic, op_str))
		ld_ins = {"addr":None, "mnem":None, "op":None}
		judge_ins = {"addr":None, "mnem":None, "op":None}
		# 寻找原子加载指令
		for (address1, size1, mnemonic1, op_str1) in md.disasm_lite(code[address-20:address], address-20):
			if (mnemonic1.upper() in exclusive_load_instructions):
				ld_ins["addr"] = address1
				ld_ins["mnem"] = mnemonic1
				ld_ins["op"] = op_str1
				break
		# 寻找条件跳转指令
		for (address2, size2, mnemonic2, op_str2) in md.disasm_lite(code[address:address+20], address):
			if (mnemonic2.upper() in exclusive_judge_instructions):
				judge_ins["addr"] = address2
				judge_ins["mnem"] = mnemonic2
				judge_ins["op"] = op_str2
				break
		print("0x%x:\t%s\t%s" %(ld_ins["addr"], ld_ins["mnem"], ld_ins["op"]))
		print("0x%x:\t%s\t%s" %(judge_ins["addr"], judge_ins["mnem"], judge_ins["op"]))
		
        	# patch load instruction
		new_ins = "ldr  " + ld_ins["op"]
		encoding, count = ks.asm(bytes(new_ins, 'utf-8'),addr=ld_ins["addr"])
		new_code[ld_ins["addr"]:ld_ins["addr"]+len(encoding)] = encoding
		
        	# patch store instruction
		new_op = re.match(r'[wx]\d+, (.*)', op_str).group(1)
		new_ins = "str  " + new_op
		encoding, count = ks.asm(bytes(new_ins, 'utf-8'),addr=address)
		new_code[address:address+len(encoding)] = encoding
		
        	# patch judge instruction
		if (judge_ins["mnem"].upper() == "CBNZ"):
			encoding, count = ks.asm(bytes("nop", 'utf-8'))
			new_code[judge_ins["addr"]:judge_ins["addr"]+len(encoding)] = encoding
		else:
			b_addr = re.match(r'.*?(#0x[a-f0-9]+)', judge_ins["op"]).group(1)
			new_ins = "b  " + b_addr
			encoding, count = ks.asm(bytes(new_ins, 'utf-8'),addr=judge_ins["addr"])
			new_code[judge_ins["addr"]:judge_ins["addr"]+len(encoding)] = encoding
new_f = open("./libxxx_patch.so", '+wb')
new_f.write(bytes(new_code))
new_f.flush()
