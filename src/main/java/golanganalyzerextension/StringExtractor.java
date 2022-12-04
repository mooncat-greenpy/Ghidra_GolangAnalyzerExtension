package golanganalyzerextension;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.OperandType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.RefType;

public class StringExtractor {

	private static final int CHECK_INST_NUM=6;

	private GolangBinary go_bin;
	private GolangAnalyzerExtensionService service;

	private Map<Long, String> string_map;

	public StringExtractor(GolangBinary go_bin, GolangAnalyzerExtensionService service) {
		this.go_bin=go_bin;
		this.service=service;

		string_map=new HashMap<Long, String>();

		search_memory();
		search_inst();

		service.store_string_map(string_map);
	}

	public Map<Long, String> get_string_map(){
		return string_map;
	}

	public void modify() {
		for(Map.Entry<Long, String> entry : string_map.entrySet()) {
			go_bin.create_label(go_bin.get_address(entry.getKey()), String.format("gos_%s_%x", entry.getValue(), entry.getKey()));
		}
	}

	private String check_string(Address addr) {
		int pointer_size=go_bin.get_pointer_size();

		if(!go_bin.is_valid_address(addr) || !go_bin.is_valid_address(addr.add(pointer_size))) {
			return null;
		}
		long str_addr_value=go_bin.get_address_value(addr, pointer_size);
		if(!go_bin.is_valid_address(str_addr_value)) {
			return null;
		}
		long str_len=go_bin.get_address_value(addr, pointer_size, pointer_size);
		if(str_len<=0 || str_len>=0x1000) {
			return null;
		}
		if(go_bin.is_valid_address(addr.add(pointer_size*2))) {
			long str_len2=go_bin.get_address_value(addr, pointer_size*2, pointer_size);
			if(str_len==str_len2) {
				return null;
			}
		}

		String str=go_bin.read_string(go_bin.get_address(str_addr_value), (int)str_len);
		if(str.length()!=str_len) {
			return null;
		}

		return str;
	}

	private String check_string(Address str_addr, long str_len) {
		String str=go_bin.read_string(str_addr, (int)str_len);
		if(str.length()!=str_len) {
			return null;
		}
		return str;
	}

	private void search_memory() {
		int pointer_size=go_bin.get_pointer_size();

		for (MemoryBlock mb : go_bin.get_memory_blocks()) {
			Address search_addr=mb.getStart();
			while(go_bin.is_valid_address(search_addr) && search_addr.getOffset()<mb.getEnd().getOffset()) {
				String str=check_string(search_addr);
				if(str==null) {
					search_addr=search_addr.add(pointer_size);
					continue;
				}

				string_map.put(search_addr.getOffset(), str);
				search_addr=search_addr.add(pointer_size*2);
			}
		}
	}

	private void search_inst() {
		for(GolangFunction go_func : service.get_function_list()) {
			search_function(go_func.get_func_addr(), (int)go_func.func_size);
		}
		// amd64
		// LEA        RCX,[0xXXXXXXXX]              : 0xXXXXXXXX: "name"
		// MOV        EDI,0x4

		// LEA        RBX,[0xXXXXXXXX]              : 0xXXXXXXXX: "name"
		// MOV        qword ptr [RSP + 0x180],RBX
		// MOV        qword ptr [RSP + 0x188],0x4

		// MOV        qword ptr [RAX + 0x8],0x4
		// CMP        dword ptr [0xYYYYYYYY],0x0
		// JNZ        0xZZZZZZZZ
		// LEA        RDX,[0xXXXXXXXX]              : 0xXXXXXXXX: "name"
		// MOV        qword ptr [RAX],RDX

		// MOV        qword ptr [RAX + 0x8],0x4
		// CMP        dword ptr [0xYYYYYYYY],0x0
		// JNZ        0xZZZZZZZZ
		// LEA        RDX,[0xXXXXXXXX]              : 0xXXXXXXXX: "name"
		// MOV        qword ptr [RAX],RDX

		// LEA        RBX,[0xXXXXXXXX]              : 0xXXXXXXXX: &"name", 4


		// arm
		// ldr        r2,[0xYYYYYYYY]               : 0xYYYYYYYY: 0xXXXXXXXX
		// str        r2,[sp,#0xc]                  : 0xXXXXXXXX: "name"
		// mov        r3,#0x4
		// str        r3,[sp,#0x10]


		// arm64
		// adrp       x2,0xb6000
		// add        x2=>DAT_000b6b98,x2,#0xb98    : 0x000b6b98: "name"
		// orr        x3,xzr,#0x4

		// orr        x1,xzr,#0x4
		// str        x1,[x0, #0x8]
		// adrp       x27,0x177000
		// add        x27,x27,#0x150
		// ldr        w2,[x27]=>DAT_00177150
		// cbnz       w2,LAB_000912d0
		// adrp       x4,0xb6000
		// add        x4=>DAT_000b6f98,x4,#0xf98
		// str        x4=>DAT_000b6f98,[x0]         : 0x000b6f98: "name"



		// mips64
		// lui        a0,0xd
		// daddu      a0,a0,gp
		// daddiu     a0,a0,0x6a96
		// sd         a0=>DAT_000d6a96,0x18(sp)     : 0x000d7a96: &"name"
		// daddiu     a1,zero,0x4
		// sd         a1,0x20(sp)

		// ld         s4,0x28(sp)
		// daddiu     v0,zero,0x4
		// sd         v0,0x8(s4)
		// lui        s7,0x1a
		// daddu      s7,s7,gp
		// lwu        v1,-0x6760(s7)
		// bne        v1,zero,bbc20
		// lui        at,0xd
		// daddu      at,at,gp
		// daddiu     at,at,0x6f39
		// sd         at=>DAT_000d6f39,0x0(s4)      : 0x000d6f39: &"name"


		// ppc64
		// lis        r5,0xb
		// addi       r5,r5,0x6a6c
		// li         r6=>DAT_000b6a6c,0x4
	}

	private void search_function(Address addr, int length) {
		Instruction inst=go_bin.get_instruction(addr);

		while(inst!=null && inst.getAddress().getOffset()<=addr.add(length).getOffset()) {
			check_insts(inst);
			inst=inst.getNext();
		}
	}

	private void check_insts(Instruction inst) {
		if(inst.getNumOperands()!=2) {
			return;
		}
		if(inst.getOperandType(0)!=OperandType.DYNAMIC || inst.getOperandType(1)!=OperandType.SCALAR) {
			return;
		}
		if(inst.getOperandRefType(0)!=RefType.WRITE || inst.getOperandRefType(1)!=RefType.DATA) {
			return;
		}

		Object[] str_len_inst_op1=inst.getOpObjects(0);
		Object[] str_len_inst_op2=inst.getOpObjects(1);
		if(str_len_inst_op1.length!=2 || str_len_inst_op2.length!=1) {
			return;
		}

		if(!(str_len_inst_op1[0] instanceof Register) || !(str_len_inst_op1[1] instanceof Scalar) || !(str_len_inst_op2[0] instanceof Scalar)) {
			return;
		}

		String base_reg=((Register)str_len_inst_op1[0]).getName();
		long string_len_offset=((Scalar)str_len_inst_op1[1]).getValue();
		long string_len=((Scalar)str_len_inst_op2[0]).getValue();

		Instruction check_inst=inst;
		for(int i=0; i<CHECK_INST_NUM; i++) {
			if(check_inst.getPrevious()==null) {
				break;
			}
			check_inst=check_inst.getPrevious();
		}

		Map<Register, Address> reg_map=new HashMap<>();
		for(int i=0; i<CHECK_INST_NUM*2 && check_inst!=null; i++) {
			if(is_move_addr_to_reg(check_inst)) {
				Object[] op1=check_inst.getOpObjects(0);
				Object[] op2=check_inst.getOpObjects(1);
				reg_map.put((Register)op1[0], (Address)op2[0]);
				check_inst=check_inst.getNext();
				continue;
			} else if (is_move_scalar_to_reg(check_inst)) {
				Object[] op1=check_inst.getOpObjects(0);
				Object[] op2=check_inst.getOpObjects(1);
				reg_map.put((Register)op1[0], go_bin.get_address(((Scalar)op2[0]).getValue()));
				check_inst=check_inst.getNext();
				continue;
			} else if (is_move_reg_to_addr_reg(check_inst)) {
				Object[] op1=check_inst.getOpObjects(0);
				Object[] op2=check_inst.getOpObjects(1);
				Address data=reg_map.get((Register)op2[0]);
				if(data!=null && ((Register)op1[0]).getName().equals(base_reg) && string_len_offset==go_bin.get_pointer_size()) {
					String str=check_string(data, string_len);
					if(str!=null) {
						string_map.put(data.getOffset(), str);
						continue;
					}
				}
			} else if (is_move_reg_to_addr_reg_scalar(check_inst)) {
				Object[] op1=check_inst.getOpObjects(0);
				Object[] op2=check_inst.getOpObjects(1);
				Address data=reg_map.get((Register)op2[0]);
				if(data!=null && ((Register)op1[0]).getName().equals(base_reg) && string_len_offset==((Scalar)op1[1]).getValue()+go_bin.get_pointer_size()) {
					String str=check_string(data, string_len);
					if(str!=null) {
						string_map.put(data.getOffset(), str);
						continue;
					}
				}
			} else {
				clear_reg_move_any_to_reg(reg_map, check_inst);
			}

			check_inst=check_inst.getNext();
		}
	}

	private boolean clear_reg_move_any_to_reg(Map<Register, Address> reg_map, Instruction inst) {
		for(int i=0; i<inst.getNumOperands(); i++) {
			if((inst.getOperandType(i)&OperandType.REGISTER)==0) {
				continue;
			}
			if(inst.getOperandRefType(i)!=RefType.WRITE && inst.getOperandRefType(i)!=RefType.READ_WRITE) {
				continue;
			}

			for(Object op : inst.getOpObjects(i)) {
				if(!(op instanceof Register)) {
					continue;
				}
				reg_map.remove((Register)op);
			}
		}
		return false;
	}

	private boolean is_move_addr_to_reg(Instruction inst) {
		if(inst.getNumOperands()!=2) {
			return false;
		}
		if(inst.getOperandType(0)!=OperandType.REGISTER || inst.getOperandType(1)!=(OperandType.ADDRESS|OperandType.DATA)) {
			return false;
		}
		if(inst.getOperandRefType(0)!=RefType.WRITE || inst.getOperandRefType(1)!=RefType.READ) {
			return false;
		}
		Object[] op1=inst.getOpObjects(0);
		Object[] op2=inst.getOpObjects(1);
		if(op1.length!=1 && op2.length!=1) {
			return false;
		}
		if(!(op1[0] instanceof Register) || !(op2[0] instanceof Address)) {
			return false;
		}

		return true;
	}

	private boolean is_move_scalar_to_reg(Instruction inst) {
		if(inst.getNumOperands()!=2) {
			return false;
		}
		if(inst.getOperandType(0)!=OperandType.REGISTER || inst.getOperandType(1)!=(OperandType.ADDRESS|OperandType.SCALAR)) {
			return false;
		}
		if(inst.getOperandRefType(0)!=RefType.WRITE || inst.getOperandRefType(1)!=RefType.DATA) {
			return false;
		}
		Object[] op1=inst.getOpObjects(0);
		Object[] op2=inst.getOpObjects(1);
		if(op1.length!=1 && op2.length!=1) {
			return false;
		}
		if(!(op1[0] instanceof Register) || !(op2[0] instanceof Scalar)) {
			return false;
		}

		return true;
	}

	private boolean is_move_reg_to_addr_reg(Instruction inst) {
		if(inst.getNumOperands()!=2) {
			return false;
		}
		if(inst.getOperandType(0)!=OperandType.DYNAMIC || (inst.getOperandType(1)|(OperandType.REGISTER))==0) {// mov [rax],rdx ADDR|REG(lea), mov [rax+0x100],rdx REG(mov)
			return false;
		}
		if(inst.getOperandRefType(0)!=RefType.WRITE || inst.getOperandRefType(1)!=RefType.READ) {
			return false;
		}
		Object[] op1=inst.getOpObjects(0);
		Object[] op2=inst.getOpObjects(1);
		if(op1.length!=1 || op2.length!=1) {
			return false;
		}
		if(!(op1[0] instanceof Register) || !(op2[0] instanceof Register)) {
			return false;
		}

		return true;
	}

	private boolean is_move_reg_to_addr_reg_scalar(Instruction inst) {
		if(inst.getNumOperands()!=2) {
			return false;
		}
		if(inst.getOperandType(0)!=OperandType.DYNAMIC || (inst.getOperandType(1)|(OperandType.REGISTER))==0) {// x64 reg only x86 reg|scalar
			return false;
		}
		if(inst.getOperandRefType(0)!=RefType.WRITE || inst.getOperandRefType(1)!=RefType.READ) {
			return false;
		}
		Object[] op1=inst.getOpObjects(0);
		Object[] op2=inst.getOpObjects(1);
		if(op1.length!=2 || op2.length!=1) {
			return false;
		}
		if(!(op1[0] instanceof Register) || !(op1[1] instanceof Scalar) || !(op2[0] instanceof Register)) {
			return false;
		}

		return true;
	}
}
