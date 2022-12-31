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
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;

public class StringExtractor {

	private static final int CHECK_INST_NUM=6;

	private GolangBinary go_bin;
	private GolangAnalyzerExtensionService service;

	private Map<Long, GolangString> string_map;

	public StringExtractor(GolangBinary go_bin, GolangAnalyzerExtensionService service) {
		this.go_bin=go_bin;
		this.service=service;

		string_map=new HashMap<Long, GolangString>();

		search_memory();
		search_inst();

		service.store_string_map(string_map);
	}

	public Map<Long, GolangString> get_string_map(){
		return string_map;
	}

	public void modify() {
		for(GolangString entry : string_map.values()) {
			if(entry.get_is_struct()) {
				go_bin.create_label(entry.get_addr(), String.format("goss_%s_%x", entry.get_str(), entry.get_addr().getOffset()));
				Address str_addr=go_bin.get_address(go_bin.get_address_value(entry.get_addr(), go_bin.get_pointer_size()));
				if(str_addr==null) {
					continue;
				}
				go_bin.create_string_data(str_addr, entry.get_str().length());
			} else {
				go_bin.create_label(entry.get_addr(), String.format("gos_%s_%x", entry.get_str(), entry.get_addr().getOffset()));
				go_bin.create_string_data(entry.get_addr(), entry.get_str().length());
			}
		}
	}

	private void search_memory() {
		int pointer_size=go_bin.get_pointer_size();

		for (MemoryBlock mb : go_bin.get_memory_blocks()) {
			Address search_addr=mb.getStart();
			while(go_bin.is_valid_address(search_addr) && search_addr.getOffset()<mb.getEnd().getOffset()) {
				try {
					GolangString str=GolangString.create_string_struct(go_bin, search_addr);
					string_map.put(search_addr.getOffset(), str);
					search_addr=search_addr.add(pointer_size*2);
				} catch (InvalidBinaryStructureException e) {
					search_addr=search_addr.add(pointer_size);
				}
			}
		}
	}

	private void search_inst() {
		for(GolangFunction go_func : service.get_function_list()) {
			search_function(go_func.get_func_addr(), (int)go_func.func_size);
		}
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
		int string_len=(int)((Scalar)str_len_inst_op2[0]).getValue();
		if(string_len<=0) {
			return;
		}

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
					try {
						GolangString str=GolangString.create_string(go_bin, data, string_len);
						string_map.put(data.getOffset(), str);
						continue;
					} catch (InvalidBinaryStructureException e) {
						Logger.append_message(String.format("Failed to get string: %s", e.getMessage()));
					}
				}
			} else if (is_move_reg_to_addr_reg_scalar(check_inst)) {
				Object[] op1=check_inst.getOpObjects(0);
				Object[] op2=check_inst.getOpObjects(1);
				Address data=reg_map.get((Register)op2[0]);
				if(data!=null && ((Register)op1[0]).getName().equals(base_reg) && string_len_offset==((Scalar)op1[1]).getValue()+go_bin.get_pointer_size()) {
					try {
						GolangString str=GolangString.create_string(go_bin, data, string_len);
						string_map.put(data.getOffset(), str);
						continue;
					} catch (InvalidBinaryStructureException e) {
						Logger.append_message(String.format("Failed to get string: %s", e.getMessage()));
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
