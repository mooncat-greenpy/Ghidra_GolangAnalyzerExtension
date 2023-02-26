package golanganalyzerextension.function;

import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;

public class GolangFunctionRiscv extends GolangFunction {

	private static final String[] reg_arg_str={"a0", "a1", "a2", "a3", "a4", "a5", "a6", "a7", "s0", "s1", "s2", "s3", "s4", "s5", "s6", "s7"};

	GolangFunctionRiscv(GolangBinary go_bin, GolangAnalyzerExtensionService service, Address func_info_addr, long func_size, boolean disasm_option, boolean extended_option) {
		super(go_bin, service, func_info_addr, func_size, disasm_option, extended_option);
	}

	GolangFunctionRiscv(GolangBinary go_bin, GolangAnalyzerExtensionService service, Function func, boolean disasm_option, boolean extended_option) {
		super(go_bin, service, func, disasm_option, extended_option);
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
		if(go_bin.lt_go_version("go1.18beta1") || go_bin.get_pointer_size()!=8) {
			return false;
		}
		return true;
	}
}
