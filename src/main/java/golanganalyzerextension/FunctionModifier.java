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
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.function.FileLine;
import golanganalyzerextension.function.GolangFunction;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;


// debug/gosym/pclntab.go
public class FunctionModifier {
	private GolangBinary go_bin;
	private GolangAnalyzerExtensionService service;

	private long func_num;
	private List<GolangFunction> gofunc_list;
	private List<String> file_name_list;

	private boolean rename_option;
	private boolean param_option;
	private boolean comment_option;
	private boolean disasm_option;

	private boolean ok;

	public FunctionModifier(GolangBinary go_bin, GolangAnalyzerExtensionService service, boolean rename_option, boolean param_option, boolean comment_option, boolean disasm_option) {
		this.go_bin=go_bin;
		this.service=service;

		this.func_num=0;
		this.gofunc_list=new ArrayList<>();
		this.file_name_list=new ArrayList<>();

		this.rename_option=rename_option;
		this.param_option=param_option;
		this.comment_option=comment_option;
		this.disasm_option=disasm_option;

		this.ok=false;

		if(!rename_option && !param_option && !comment_option) {
			return;
		}

		if(!init_file_name_list()) {
			return;
		}
		if(!init_functions()) {
			return;
		}

		init_hardcode_functions();

		service.store_function_list(gofunc_list);

		this.ok=true;
	}

	public boolean is_ok() {
		return ok;
	}

	public void modify() {
		if(!ok) {
			Logger.append_message("Failed to setup FunctionModifier");
			return;
		}

		for(GolangFunction gofunc: gofunc_list) {
			if(rename_option) {
				rename_func(gofunc);
			}
			if(param_option) {
				modify_func_param(gofunc);
			}
			if(comment_option) {
				add_func_info_comment(gofunc);
				add_file_line_comment(gofunc);
			}
		}
	}

	private boolean init_file_name_list() {
		boolean is_go116=false;
		boolean is_go18=false;
		if(go_bin.ge_go_version("go1.16beta1")) {
			is_go116=true;
		}
		if(go_bin.ge_go_version("go1.8beta1")) {
			is_go18=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address pcheader_base=go_bin.get_pcheader_base();

		try {
			func_num=go_bin.get_address_value(pcheader_base, 8, pointer_size);
			file_name_list=new ArrayList<>();
			if(is_go116) {
				return true;
			}
			Address func_list_base=go_bin.get_address(pcheader_base, 8+pointer_size);

			long file_name_table_offset=go_bin.get_address_value(func_list_base, func_num*pointer_size*2+pointer_size, 4);
			Address file_name_table=go_bin.get_address(pcheader_base, file_name_table_offset);
			long file_name_table_size=go_bin.get_address_value(file_name_table, 4);
			if(file_name_table_size==0) {
				return false;
			}

			for(int i=1;i<file_name_table_size+(is_go18?0:1);i++) {
				long file_name_offset=go_bin.get_address_value(file_name_table, 4*i,4);
				if(file_name_offset==0) {
					return false;
				}
				Address file_name_addr=go_bin.get_address(pcheader_base, file_name_offset);
				file_name_list.add(go_bin.create_string_data(file_name_addr).orElse(String.format("not_found_%x", file_name_addr.getOffset())));
			}

			service.store_filename_list(file_name_list);

			return true;
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to init file name list: pcheader_addr=%s, message=%s", pcheader_base, e.getMessage()));
			return false;
		}
	}

	private boolean init_functions() {
		boolean is_go116=false;
		boolean is_go118=false;
		if(go_bin.ge_go_version("go1.16beta1")) {
			is_go116=true;
		}
		if(go_bin.ge_go_version("go1.18beta1")) {
			is_go118=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address pcheader_base=go_bin.get_pcheader_base();

		gofunc_list=new ArrayList<>();
		Address func_list_base;
		try {
			if(is_go118) {
				func_list_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*7, pointer_size));
			}else if(is_go116) {
				func_list_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*6, pointer_size));
			}else {
				func_list_base=go_bin.get_address(pcheader_base, 8+pointer_size);
			}
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to init funcs: pcheader_addr=%s, message=%s", pcheader_base, e.getMessage()));
			return false;
		}

		for(int i=0; i<func_num; i++) {
			long func_addr_value;
			long func_info_offset;
			Address func_info_addr;
			long func_entry_value;
			long func_end_value;
			try {
				func_addr_value=go_bin.get_address_value(func_list_base, i*(is_go118?4:pointer_size)*2, is_go118?4:pointer_size);
				if(is_go118) {
					func_addr_value+=go_bin.get_address_value(pcheader_base, 8+pointer_size*2, pointer_size);
				}
				func_info_offset=go_bin.get_address_value(func_list_base, i*(is_go118?4:pointer_size)*2+(is_go118?4:pointer_size), is_go118?4:pointer_size);

				if(is_go116) {
					func_info_addr=go_bin.get_address(func_list_base, func_info_offset);
				}else {
					func_info_addr=go_bin.get_address(pcheader_base, func_info_offset);
				}

				func_entry_value=go_bin.get_address_value(func_info_addr, is_go118?4:pointer_size);
				func_end_value=go_bin.get_address_value(func_list_base, i*(is_go118?4:pointer_size)*2+(is_go118?4:pointer_size)*2, is_go118?4:pointer_size);
				if(is_go118) {
					func_entry_value+=go_bin.get_address_value(pcheader_base, 8+pointer_size*2, pointer_size);
					func_end_value+=go_bin.get_address_value(pcheader_base, 8+pointer_size*2, pointer_size);
				}
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to init func: pcheader_addr=%s, func_list_base=%s, i=%d, message=%s", pcheader_base, func_list_base, i, e.getMessage()));
				return false;
			}

			if(func_addr_value==0 || func_info_offset==0 || func_entry_value==0) {
				return false;
			}
			if(func_addr_value!=func_entry_value)
			{
				Logger.append_message(String.format("Function addr mismatch: %x != %x", func_addr_value, func_entry_value));
				continue;
			}

			try {
				GolangFunction gofunc=GolangFunction.create_function(go_bin, service, func_info_addr, func_end_value-func_entry_value, disasm_option);
				gofunc_list.add(gofunc);
			} catch (InvalidBinaryStructureException e) {
				Logger.append_message(String.format("Failed to create function: %s", e.getMessage()));
			}
		}
		return true;
	}

	private boolean init_hardcode_functions(){
		for(Function func : go_bin.get_functions()) {
			Address entry_addr=func.getEntryPoint();
			GolangFunction find=gofunc_list.stream().filter(v -> v.get_func_addr().equals(entry_addr)).findFirst().orElse(null);
			if(find!=null) {
				continue;
			}
			try {
				GolangFunction gofunc=GolangFunction.create_function_in_function(go_bin, service, func, disasm_option);
				gofunc_list.add(gofunc);
			} catch (InvalidBinaryStructureException e) {
				Logger.append_message(String.format("Failed to create hardcode function: %s", e.getMessage()));
			}
		}
		return true;
	}

	private void rename_func(GolangFunction gofunc) {
		Function func=gofunc.get_func();
		String func_name=gofunc.get_func_name().replace(" ", "_");

		if(func.getName().equals(func_name)) {
			return;
		}
		try {
			func.setName(func_name, SourceType.USER_DEFINED);
		}catch(Exception e) {
			Logger.append_message(String.format("Failed to set function name: addr=%s, message=%s", gofunc.get_func_addr(), e.getMessage()));
		}
	}

	private void modify_func_param(GolangFunction gofunc) {
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

	private void add_func_info_comment(GolangFunction gofunc) {
		String comment="Name: "+gofunc.get_func_name()+"\n";
		comment+=String.format("Start: %s\n", gofunc.get_func_addr());
		try {
			comment+=String.format("End: %s", go_bin.get_address(gofunc.get_func_addr(), gofunc.get_func_size()));
			go_bin.set_comment(gofunc.get_func_addr(), ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, comment);
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to add func comment: addr=%s, name=%s, message=%s", gofunc.get_func_addr(), gofunc.get_func_name(), e.getMessage()));
		}
	}

	private void add_file_line_comment(GolangFunction gofunc) {
		Address addr=gofunc.get_func_addr();
		Map<Integer, FileLine> comment_map=gofunc.get_file_line_comment_map();

		for(Integer key: comment_map.keySet()) {
			try {
				go_bin.set_comment(go_bin.get_address(addr, key), ghidra.program.model.listing.CodeUnit.PRE_COMMENT, comment_map.get(key).toString());
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to add file line comment: addr=%s, name=%s, message=%s", gofunc.get_func_addr(), gofunc.get_func_name(), e.getMessage()));
			}
		}
	}
}
