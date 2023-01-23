import golanganalyzerextension as gae
import java.nio.ByteBuffer
import ghidra.program.model.scalar.Scalar as Scalar
import ghidra.program.model.address.Address as Address
import array
import ghidra.program.model.symbol.SourceType as SourceType
import re


def get_obfus_str(file_line):
    value_list = []
    inst = getInstructionAt(file_line.get_func_addr().add(file_line.get_offset()))
    addr_end = file_line.get_func_addr().add(file_line.get_offset()).add(file_line.get_size())
    start = -1
    while inst != None and inst.getAddress().getOffset() < addr_end.getOffset():
        if inst.getNumOperands() <2 or len(inst.getOpObjects(1)) < 1:
            inst = inst.next
            continue

        if isinstance(inst.getOpObjects(1)[0], Scalar):
            arr = scalar_to_array(inst.getOpObjects(1)[0])
            offset = 0
            if inst.getOperandType(0) == 512:
                inst = inst.next
                if len(inst.getOpObjects(0)) < 2:
                    offset = 0
                else:
                    offset = inst.getOpObjects(0)[1].getValue()
            else:
                if len(inst.getOpObjects(0)) < 2:
                    offset = 0
                else:
                    offset = inst.getOpObjects(0)[1].getValue()
            if start == -1:
                start = offset
            value_list.append((arr, offset - start))

        if "XMM" in inst.getOpObjects(0)[0].toString() and isinstance(inst.getOpObjects(1)[0], Address):
            arr = getBytes(inst.getOpObjects(1)[0], inst.getOpObjects(0)[0].getNumBytes())
            inst = inst.next
            offset = inst.getOpObjects(0)[1].getValue()
            if start == -1:
                start = offset
            value_list.append((arr, offset - start))
        inst = inst.next
    return value_list

def scalar_to_array(scal):
    size = scal.bitLength()/8
    buf = java.nio.ByteBuffer.allocate(8)
    arr = buf.putLong(scal.getValue()).array()
    arr = arr[8-size:]
    arr.reverse()
    return arr

def resolve_func_name(addr, func_list):
    for f in func_list:
        if addr == f.get_func_addr():
            return f.get_func_name()
    return ""

def check_gobfus_str_func(gofunc, func_list):
    if ".func" not in gofunc.get_func_name():
        return False
    inst = getInstructionAt(gofunc.get_func_addr())
    addr_end = gofunc.get_func_addr().add(gofunc.get_func_size())
    count = 0
    slicebytetostring_count = 0
    while inst != None and inst.getAddress().getOffset() < addr_end.getOffset():
        if not inst.getFlowType().isCall():
            inst = inst.next
            continue
        for addr in inst.getFlows():
            func_name=resolve_func_name(addr, func_list)
            if func_name == "runtime.slicebytetostring":
                slicebytetostring_count += 1
            elif func_name != "runtime.morestack_noctxt" and func_name != gofunc.get_func_name():
                return False
        inst = inst.next
    return slicebytetostring_count == 1

def deobfuscate(arr1, arr2):
    ret = array.array("b", [])
    for i in range(len(arr1)):
        ret.append(arr1[i] ^ arr2[i])
    return ret.tostring()

def main():
    consumer_list = currentProgram.getConsumerList()
    service = consumer_list[0].getService(gae.service.GolangAnalyzerExtensionService)
    func_list = service.get_function_list()
    for f in func_list:
        try:
            if not check_gobfus_str_func(f, func_list):
                continue

            keys = f.get_file_line_comment_map().keys()
            keys.sort()
            if len(keys) < 3:
                continue
            file_line1 = f.get_file_line_comment_map()[keys[1]]
            file_line2 = f.get_file_line_comment_map()[keys[2]]
            value1_list = get_obfus_str(file_line1)
            value2_list = get_obfus_str(file_line2)
            if len(value1_list) != len(value2_list):
                continue

            orig_str = ""
            for v in range(len(value1_list)):
                orig_str = orig_str[:value1_list[v][1]] + deobfuscate(value1_list[v][0], value2_list[v][0])
            print("find: %s [%s]" % (f.get_func_addr(), orig_str))
            rename_func = getFunctionAt(f.get_func_addr())
            rename_func.setName("gobfus_" + re.sub("[^a-zA-Z0-9]", "_", orig_str.replace(" ", "_").replace("\n", "_").replace("\r", "_").replace("\x90", "_")) + "_" + rename_func.getName(), SourceType.USER_DEFINED)
            setPlateComment(f.get_func_addr(), "\"\"\"" + orig_str + "\"\"\"")
        except IndexError:
            pass


if __name__ == "__main__":
    main()
