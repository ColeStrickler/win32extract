@author Cole Strickler 
@category Windows
#@keybinding 
#@menupath 
#@toolbar 



api_calls = {}
func_info = {}



for externalReference in currentProgram.getReferenceManager().getExternalReferences():
    if externalReference.getReferenceType().isCall():
	call_addr = externalReference.getFromAddress()
        api = externalReference.getExternalLocation().getLabel()
	api_calls["0x" + call_addr.toString().encode('ascii')] = api




# this function will change a Ghidra address into an integer
def AddressToInteger(addr):
    return int(addr.toString(), 16)

def GetFunctionList():
    retlist = []
    fm = currentProgram.getFunctionManager()
    functions = fm.getFunctions(True)
    for f in functions:
        retlist.append(f)
    return retlist


def GetFuncInstructions(func):
    retlist = []
    maxaddr = AddressToInteger(f.getBody().getMaxAddress())
    entry = f.getEntryPoint()
    inst = getInstructionAt(entry)
    while AddressToInteger(inst.getAddress()) <= maxaddr:
        retlist.append(inst)
        inst = inst.getNext()
    return retlist


	
funcs = GetFunctionList()

for f in funcs:
	if f.toString()[:3] == "FUN":
		try:
			inst = GetFuncInstructions(f)
		except Exception:
			continue
		if True:
	
			print(f.toString())
			for i in inst:
				pnem = i.toString()[0:4]
				if pnem == "CALL":
					op = i.getDefaultOperandRepresentation(0)

					full_addr = "0x"
					full_addr += i.getAddress().toString()
					#print(full_addr)
					
				
					if full_addr in api_calls.keys():
						print(full_addr + ": " + api_calls[full_addr])
		
		print("\n\n")

		
	
