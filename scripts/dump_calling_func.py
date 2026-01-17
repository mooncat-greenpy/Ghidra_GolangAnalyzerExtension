#@runtime Jython
#@author 
#@category 
#@keybinding 
#@menupath 
#@toolbar 


import golanganalyzerextension as gae
import json
import ghidra.util.task.TaskMonitor as TaskMonitor
import ghidra.program.model.symbol.RefType as RefType
import ghidra.program.model.listing.CodeUnit as CodeUnit


import base64

def list_called(addr, size, n):
    called = []
    inst = getInstructionAt(addr)

    while inst is not None:
        for ref in inst.getReferencesFrom():
            if ref.referenceType.isCall():
                func = currentProgram.getListing().getFunctionContaining(ref.toAddress)
                if func is not None:
                    called.append("%x_%s" % (func.getEntryPoint().getOffset(), func.getName()))
            elif ref.referenceType.isJump():
                func = currentProgram.getListing().getFunctionContaining(ref.toAddress)
                if func is not None and func.getEntryPoint() == ref.toAddress:
                    called.append("%x_%s" % (func.getEntryPoint().getOffset(), func.getName()))
        inst = getInstructionAt(inst.getAddress().add(inst.getParsedLength()))
    return called

def main():
    txt = ""

    for i in currentProgram.getListing().getFunctions(True):
        if i.getName() == "main.main":
            continue
        start = i.getBody().getMinAddress()
        end = i.getBody().getMaxAddress()
        size = end.getOffset() - start.getOffset() + 1
        comment = currentProgram.getListing().getComment(CodeUnit.PRE_COMMENT, i.getEntryPoint())
        if comment is None:
            comment = ""
        txt += i.getEntryPoint().toString() + "|" + i.getName() + "|" + comment
        for calling in list_called(start, size, i.getName()):
            txt += "|" + "_".join(calling.split("_")[1:])
        txt += "\n"
    print("Processing")
    with open("dump/calling_func_name/%s.txt" % "_".join(currentProgram.getName().split("_")[1:]), "wb") as f:
        f.write(txt.replace(u"\ufffd", "_").encode("utf-8"))# .replace(u"\ufffd", "_"))
    print("Saved")


if __name__ == "__main__":
    main()
