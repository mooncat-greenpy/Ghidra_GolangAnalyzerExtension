package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.symbol.SourceType;


// debug/gosym/pclntab.go
public class FunctionModifier{
	GolangBinary go_bin=null;

	long func_num=0;
	List<GolangFunction> gofunc_list=null;
	List<String> file_name_list=null;
	boolean rename_option=false;
	boolean param_option=false;
	boolean comment_option=false;
	boolean disasm_option=false;
	boolean extended_option=false;

	boolean ok=false;

	public FunctionModifier(GolangBinary go_bin, GolangAnalyzerExtensionService service, boolean rename_option, boolean param_option, boolean comment_option, boolean disasm_option, boolean extended_option) {
		this.go_bin=go_bin;

		this.rename_option=rename_option;
		this.param_option=param_option;
		this.comment_option=comment_option;
		this.disasm_option=disasm_option;
		this.extended_option=extended_option;

		if(!rename_option && !param_option && !comment_option) {
			return;
		}

		if(!init_file_name_list()) {
			return;
		}
		if(!init_functions()) {
			return;
		}

		if(extended_option) {
			init_hardcode_functions();
		}

		service.store_function_list(gofunc_list);

		this.ok=true;
	}

	boolean is_ok() {
		return ok;
	}

	boolean init_file_name_list() {
		boolean is_go116=false;
		if(go_bin.compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address gopclntab_base=go_bin.get_gopclntab_base();
		func_num=go_bin.get_address_value(gopclntab_base, 8, pointer_size);
		file_name_list=new ArrayList<>();
		if(is_go116) {
			return true;
		}
		Address func_list_base=go_bin.get_address(gopclntab_base, 8+pointer_size);
		if(func_list_base==null) {
			return false;
		}

		long file_name_table_offset=go_bin.get_address_value(func_list_base, func_num*pointer_size*2+pointer_size, pointer_size);
		Address file_name_table=go_bin.get_address(gopclntab_base, file_name_table_offset);
		long file_name_table_size=go_bin.get_address_value(file_name_table, 4);
		if(file_name_table==null || file_name_table_size==0) {
			return false;
		}

		for(int i=1;i<file_name_table_size;i++) {
			long file_name_offset=go_bin.get_address_value(file_name_table, 4*i,4);
			if(file_name_offset==0) {
				return false;
			}
			Address file_name_addr=go_bin.get_address(gopclntab_base, file_name_offset);
			if(file_name_addr==null) {
				return false;
			}
			file_name_list.add(go_bin.create_string_data(file_name_addr));
		}
		return true;
	}

	boolean init_functions() {
		boolean is_go116=false;
		boolean is_go118=false;
		if(go_bin.compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}
		if(go_bin.compare_go_version("go1.18beta1")<=0) {
			is_go118=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address gopclntab_base=go_bin.get_gopclntab_base();
		gofunc_list=new ArrayList<>();
		Address func_list_base=null;
		if(is_go118) {
			func_list_base=go_bin.get_address(gopclntab_base, go_bin.get_address_value(gopclntab_base, 8+pointer_size*7, pointer_size));
		}else if(is_go116) {
			func_list_base=go_bin.get_address(gopclntab_base, go_bin.get_address_value(gopclntab_base, 8+pointer_size*6, pointer_size));
		}else {
			func_list_base=go_bin.get_address(gopclntab_base, 8+pointer_size);
		}
		if(func_list_base==null) {
			return false;
		}

		for(int i=0; i<func_num; i++) {
			long func_addr_value=go_bin.get_address_value(func_list_base, i*(is_go118?4:pointer_size)*2, is_go118?4:pointer_size);
			if(is_go118) {
				func_addr_value+=go_bin.get_address_value(gopclntab_base, 8+pointer_size*2, pointer_size);
			}
			long func_info_offset=go_bin.get_address_value(func_list_base, i*(is_go118?4:pointer_size)*2+(is_go118?4:pointer_size), is_go118?4:pointer_size);
			Address func_info_addr=null;
			if(is_go116) {
				func_info_addr=go_bin.get_address(func_list_base, func_info_offset);
			}else {
				func_info_addr=go_bin.get_address(gopclntab_base, func_info_offset);
			}

			long func_entry_value=go_bin.get_address_value(func_info_addr, is_go118?4:pointer_size);
			long func_end_value=go_bin.get_address_value(func_list_base, i*(is_go118?4:pointer_size)*2+(is_go118?4:pointer_size)*2, is_go118?4:pointer_size);
			if(is_go118) {
				func_entry_value+=go_bin.get_address_value(gopclntab_base, 8+pointer_size*2, pointer_size);
				func_end_value+=go_bin.get_address_value(gopclntab_base, 8+pointer_size*2, pointer_size);
			}

			if(func_addr_value==0 || func_info_offset==0 || func_entry_value==0) {
				return false;
			}
			if(func_addr_value!=func_entry_value)
			{
				Logger.append_message(String.format("Function addr mismatch: %x != %x", func_addr_value, func_entry_value));
				continue;
			}

			GolangFunction gofunc=null;
			if(go_bin.is_x86()) {
				gofunc=new GolangFunctionX86(go_bin, func_info_addr, func_end_value-func_entry_value, file_name_list, disasm_option, extended_option);
			}else if(go_bin.is_arm()) {
				gofunc=new GolangFunctionArm(go_bin, func_info_addr, func_end_value-func_entry_value, file_name_list, disasm_option, extended_option);
			}else {
				gofunc=new GolangFunction(go_bin, func_info_addr, func_end_value-func_entry_value, file_name_list, disasm_option, extended_option);
			}
			gofunc_list.add(gofunc);
		}
		return true;
	}

	boolean init_hardcode_functions(){
		for(Function func : go_bin.get_functions()) {
			Address entry_addr=func.getEntryPoint();
			GolangFunction find=gofunc_list.stream().filter(v -> v.func_addr.equals(entry_addr)).findFirst().orElse(null);
			if(find!=null) {
				continue;
			}
			GolangFunction gofunc=null;
			if(go_bin.is_x86()) {
				gofunc=new GolangFunctionX86(go_bin, func, disasm_option, extended_option);
			}else if(go_bin.is_arm()) {
				gofunc=new GolangFunctionArm(go_bin, func, disasm_option, extended_option);
			}else {
				gofunc=new GolangFunction(go_bin, func, disasm_option, extended_option);
			}
			if(gofunc.is_ok()) {
				gofunc_list.add(gofunc);
			}
		}
		return true;
	}

	void modify() {
		if(!ok) {
			Logger.append_message("Failed to setup FunctionModifier");
			return;
		}

		for(GolangFunction gofunc: gofunc_list) {
			if(!gofunc.is_ok()) {
				continue;
			}
			if(rename_option) {
				rename_func(gofunc);
			}
			if(param_option) {
				modify_func_param(gofunc);
			}
			if(comment_option) {
				add_func_comment(gofunc);
			}
		}
	}

	void rename_func(GolangFunction gofunc) {
		Function func=gofunc.get_func();
		String func_name=gofunc.get_func_name();

		if(func_name.equals("not found") || func.getName().equals(func_name)) {
			return;
		}
		try {
			func.setName(func_name, SourceType.USER_DEFINED);
		}catch(Exception e) {
			Logger.append_message(String.format("Failed to set function name: %s", e.getMessage()));
		}
	}

	void modify_func_param(GolangFunction gofunc) {
		Function func=gofunc.get_func();
		List<Parameter> new_params=gofunc.get_params();
		if(new_params==null) {
			return;
		}

		try {
			func.updateFunction(null, null, new_params, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
			func.setReturnType(new VoidDataType(), SourceType.USER_DEFINED);
		}catch(Exception e) {
			Logger.append_message(String.format("Failed to set function parameters: %s", e.getMessage()));
		}
	}

	void add_func_comment(GolangFunction gofunc) {
		Address addr=gofunc.get_func_addr();
		Map<Integer, String> comment_map=gofunc.get_file_line_comment_map();

		for(Integer key: comment_map.keySet()) {
			go_bin.set_comment(go_bin.get_address(addr, key), ghidra.program.model.listing.CodeUnit.PRE_COMMENT, comment_map.get(key));
		}
	}
}
