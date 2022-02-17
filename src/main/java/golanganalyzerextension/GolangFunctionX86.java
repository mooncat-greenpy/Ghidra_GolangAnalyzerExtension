package golanganalyzerextension;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.scalar.Scalar;


public class GolangFunctionX86 extends GolangFunction {

	public GolangFunctionX86(GolangBinary go_bin, Address func_info_addr, long func_size, List<String> file_name_list, boolean extended_option) {
		super(go_bin, func_info_addr, func_size, file_name_list, extended_option);
	}

	private static final String[] reg_arg_str={"RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11"};

	@Override
	boolean check_inst_builtin_reg_arg(Instruction inst, Map<Register, REG_FLAG> builtin_reg_state, List<Register> reg_arg) {
		if(inst.getMnemonicString().equals("RET") || inst.getMnemonicString().equals("JMP")) {
			return true;
		}
		Object op_input[]=inst.getInputObjects();
		Object op_output[]=inst.getResultObjects();

		for(int j=0;j<op_input.length;j++) {
			if(!(op_input[j] instanceof Register)) {
				continue;
			}
			Register reg=(Register)op_input[j];
			if(inst.getMnemonicString().equals("XOR") &&
					(inst.getNumOperands()==2 && inst.getOpObjects(0).length>0 && inst.getOpObjects(1).length>0 &&
					inst.getOpObjects(0)[0].toString().equals(inst.getOpObjects(1)[0].toString()))) {
				continue;
			}
			if(inst.getMnemonicString().equals("PUSH") || inst.getMnemonicString().equals("XCHG")) {
				continue;
			}
			if(!builtin_reg_state.containsKey(reg.getBaseRegister()) &&
					inst.toString().contains(reg.toString()) &&
					(reg.getTypeFlags()&(Register.TYPE_PC|Register.TYPE_SP))==0 &&
					!reg.toString().contains("SP") &&
					// XMM15 is used as a zero register.
					!go_bin.compare_register(reg, go_bin.get_register("BP")) && !go_bin.compare_register(reg, go_bin.get_register("XMM15"))) {
				builtin_reg_state.put(reg.getBaseRegister(), REG_FLAG.READ);
				reg_arg.add(reg);
			}
		}
		for(int j=0;j<op_output.length;j++) {
			if(!(op_output[j] instanceof Register)) {
				continue;
			}
			Register reg=(Register)op_output[j];
			if(!builtin_reg_state.containsKey(reg.getBaseRegister())) {
				builtin_reg_state.put(reg.getBaseRegister(), REG_FLAG.WRITE);
			}
		}
		return false;
	}

	@Override
	String get_reg_arg_name(int arg_count) {
		if(arg_count<0 || reg_arg_str.length<=arg_count) {
			return "";
		}
		return reg_arg_str[arg_count];
	}

	@Override
	boolean check_inst_reg_arg(Instruction inst, Map<Register, REG_FLAG> builtin_reg_state) {
		if(go_bin.compare_go_version("go1.17beta1")>0) {
			return false;
		}
		String mnemonic=inst.getMnemonicString();
		if(!mnemonic.equals("MOV") || inst.getNumOperands()<2) {
			return false;
		}

		Object op1[]=inst.getOpObjects(0);
		Object op2[]=inst.getOpObjects(1);
		if(op1.length<2 || op2.length<1) {
			return false;
		}

		if(!op1[0].toString().equals("RSP") ||
				!(op1[1] instanceof Scalar)) {
			return false;
		}

		boolean is_target=false;
		for(int i=0;i<reg_arg_str.length;i++) {
			if(!reg_arg_str[i].equals(op2[0].toString())) {
				continue;
			}
			is_target=true;
			break;
		}
		if(is_target) {
			Register reg=(Register)op2[0];
			if(builtin_reg_state.containsKey(reg.getBaseRegister()) && builtin_reg_state.get(reg.getBaseRegister())==REG_FLAG.WRITE) {
				return false;
			}
			return true;
		}
		return false;
	}
}
