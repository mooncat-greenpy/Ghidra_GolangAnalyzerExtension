package golanganalyzerextension.function;

import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;
import golanganalyzerextension.version.GolangVersion;

public class GolangFunctionPpc extends GolangFunction {

	private static final String[] reg_arg_str={"r3", "r4", "r5", "r6", "r7", "r8", "r9", "r10", "r14", "r15", "r16", "r17"};

	GolangFunctionPpc(GolangBinary go_bin, GolangAnalyzerExtensionService service, Address func_info_addr, long func_size, boolean disasm_option) {
		super(go_bin, service, func_info_addr, func_size, disasm_option);
	}

	GolangFunctionPpc(GolangBinary go_bin, GolangAnalyzerExtensionService service, Function func, boolean disasm_option) {
		super(go_bin, service, func, disasm_option);
	}

	@Override
	String get_reg_arg_name(int arg_count) {
		if(arg_count<0 || reg_arg_str.length<=arg_count) {
			return "";
		}
		return reg_arg_str[arg_count];
	}

	@Override
	int get_reg_arg_count() {
		return reg_arg_str.length;
	}

	@Override
	int get_arg_stack_base() {
		return go_bin.get_pointer_size()*3;
	}

	@Override
	boolean check_inst_reg_arg(Instruction inst, Map<Register, REG_FLAG> builtin_reg_state) {
		if(go_bin.lt_go_version(GolangVersion.GO_1_18_LOWEST) || go_bin.get_pointer_size()!=8) {
			return false;
		}
		return true;
	}
}
