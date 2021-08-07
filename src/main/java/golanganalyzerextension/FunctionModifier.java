package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;


public class FunctionModifier extends GolangBinary {
	long func_num=0;
	List<GolangFunction> gofunc_list=null;
	List<String> file_name_list=null;

	public FunctionModifier(Program program, TaskMonitor monitor, MessageLog log, boolean debugmode) {
		super(program, monitor, log, debugmode);

		if(!init_gopclntab()) {
			return;
		}
		if(!init_file_name_list()) {
			return;
		}
		if(!init_functions()) {
			return;
		}
		ok=true;
	}

	boolean init_file_name_list() {
		func_num=get_address_value(get_address(gopclntab_base, 8), pointer_size);
		file_name_list=new ArrayList<>();
		Address func_list_base=get_address(gopclntab_base, 8+pointer_size);
		if(func_list_base==null) {
			return false;
		}

		long file_name_table_offset=get_address_value(get_address(func_list_base, func_num*pointer_size*2+pointer_size), pointer_size);
		Address file_name_table=get_address(gopclntab_base, file_name_table_offset);
		if(file_name_table==null) {
			return false;
		}

		long file_name_table_size=get_address_value(file_name_table, 4);
		for(int i=1;i<file_name_table_size;i++) {
			long file_name_offset=get_address_value(get_address(file_name_table, 4*i),4);
			if(file_name_offset==0) {
				return false;
			}
			String file_name=create_string_data(get_address(gopclntab_base, file_name_offset));
			file_name_list.add(file_name);
		}
		return true;
	}

	boolean init_functions() {
		gofunc_list=new ArrayList<>();
		Address func_list_base=get_address(gopclntab_base, 8+pointer_size);
		if(func_list_base==null) {
			return false;
		}
		for(int i=0; i<func_num; i++) {
			long func_addr_value=get_address_value(get_address(func_list_base, i*pointer_size*2), pointer_size);
			long func_info_offset=get_address_value(get_address(func_list_base, i*pointer_size*2+pointer_size), pointer_size);
			long func_entry_value=get_address_value(get_address(gopclntab_base, func_info_offset), pointer_size);
			if(func_addr_value==0 || func_info_offset==0 || func_entry_value==0) {
				return false;
			}
			if(func_addr_value!=func_entry_value)
			{
				append_message(String.format("Function addr mismatch: %x != %x", func_addr_value, func_entry_value));
				continue;
			}

			GolangFunction gofunc=new GolangFunction(program, monitor, log, gopclntab_base, func_info_offset, file_name_list, debugmode);
			gofunc_list.add(gofunc);
		}
		return true;
	}

	void modify(boolean rename_option, boolean param_option, boolean comment_option) {
		if(!ok) {
			append_message("Failed to setup FunctionModifier");
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
			func.setName(func_name, SourceType.ANALYSIS);
		}catch(Exception e) {
			append_message(String.format("Failed to set function name: %s", e.getMessage()));
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
			func.setReturnType(DataType.VOID, SourceType.USER_DEFINED);
		}catch(Exception e) {
			append_message(String.format("Failed to set function parameters: %s", e.getMessage()));
		}
	}

	void add_func_comment(GolangFunction gofunc) {
		Address addr=gofunc.get_func_addr();
		Map<Integer, String> comment_map=gofunc.get_file_line_comment_map();

		for(Integer key: comment_map.keySet()) {
			program_listing.setComment(get_address(addr, key), ghidra.program.model.listing.CodeUnit.PRE_COMMENT, comment_map.get(key));
		}
	}
}
