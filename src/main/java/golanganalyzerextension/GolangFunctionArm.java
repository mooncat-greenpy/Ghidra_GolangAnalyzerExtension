package golanganalyzerextension;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Instruction;


public class GolangFunctionArm extends GolangFunction {

	public GolangFunctionArm(GolangBinary go_bin, Address func_info_addr, long func_size, List<String> file_name_list, boolean extended_option) {
		super(go_bin, func_info_addr, func_size, file_name_list, extended_option);
	}

	private static final String[] reg_arg_str={};

	@Override
	boolean check_inst_builtin_reg_arg(Instruction inst, Map<Register, REG_FLAG> builtin_reg_state, List<Register> reg_arg) {
		if(inst.getMnemonicString().equals("ret") || inst.getMnemonicString().equals("b")) {
			return true;
		}
		Object op_input[]=inst.getInputObjects();
		Object op_output[]=inst.getResultObjects();

		for(int j=0;j<op_input.length;j++) {
			if(!(op_input[j] instanceof Register)) {
				continue;
			}
			Register reg=(Register)op_input[j];
			if(!builtin_reg_state.containsKey(reg.getBaseRegister()) &&
					inst.toString().contains(reg.toString()) &&
					(reg.getTypeFlags()&(Register.TYPE_PC|Register.TYPE_SP))==0 &&
					!reg.toString().contains("sp") &&
					!go_bin.compare_register(reg, go_bin.get_register("lr"))) {
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
}
