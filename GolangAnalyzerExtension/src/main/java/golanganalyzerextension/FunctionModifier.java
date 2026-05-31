package golanganalyzerextension;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.InstructionIterator;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.function.FileLine;
import golanganalyzerextension.function.GolangFunction;
import golanganalyzerextension.gobinary.FuncInfo;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;
import golanganalyzerextension.version.GolangVersion;


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
	private boolean force;

	private boolean ok;

	public FunctionModifier(GolangBinary go_bin, GolangAnalyzerExtensionService service, boolean rename_option, boolean param_option, boolean comment_option, boolean disasm_option, boolean force) {
		this.go_bin=go_bin;
		this.service=service;

		this.func_num=0;
		this.gofunc_list=new ArrayList<>();
		this.file_name_list=new ArrayList<>();

		this.rename_option=rename_option;
		this.param_option=param_option;
		this.comment_option=comment_option;
		this.disasm_option=disasm_option;
		this.force=force;

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
		if(go_bin.ge_go_version(GolangVersion.GO_1_16_LOWEST)) {
			is_go116=true;
		}
		if(go_bin.ge_go_version(GolangVersion.GO_1_8_LOWEST)) {
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
		if(go_bin.ge_go_version(GolangVersion.GO_1_16_LOWEST)) {
			is_go116=true;
		}
		if(go_bin.ge_go_version(GolangVersion.GO_1_18_LOWEST)) {
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
			FuncInfo info;
			try {
				int functab_field_size=is_go118?4:pointer_size;
				info=new FuncInfo(go_bin, func_list_base, go_bin.get_address(func_list_base, i*functab_field_size*2), force);
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to get func info: pcheader_addr=%s, func_list_base=%s, i=%d, message=%s", pcheader_base, func_list_base, i, e.getMessage()));
				continue;
			}
			if (info==null) {
				Logger.append_message(String.format("Failed to get func info: pcheader_addr=%s, func_list_base=%s, i=%d", pcheader_base, func_list_base, i));
				continue;
			}

			try {
				GolangFunction gofunc=GolangFunction.create_function(go_bin, service, info, disasm_option);
				gofunc_list.add(gofunc);
			} catch (InvalidBinaryStructureException e) {
				Logger.append_message(String.format("Failed to create function: %s", e.getMessage()));
			}
		}
		return true;
	}

	private boolean init_hardcode_functions(){
		// On WASM the WasmLoader has already created a function for every entry in the
		// module (often >1000). The memcpy/memset disassembly heuristics here aren't
		// meaningful for WASM and just produce noisy logs, so skip the pass.
		if (go_bin.is_wasm()) {
			return true;
		}
		for(Function func : go_bin.get_functions()) {
			Address entry_addr=func.getEntryPoint();
			GolangFunction find=gofunc_list.stream().filter(v -> v.get_func_addr().equals(entry_addr)).findFirst().orElse(null);
			if(find!=null) {
				continue;
			}
			try {
				GolangFunction gofunc=GolangFunction.create_chk_copy_or_set_function(go_bin, service, func, disasm_option);
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
			func.setReturnType(new VoidDataType(), SourceType.USER_DEFINED);
			func.updateFunction(null, gofunc.get_ret_param().orElse(null), new_params, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
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

		if (go_bin.is_wasm()) {
			add_file_line_comment_wasm(gofunc, comment_map);
			return;
		}

		for(Integer key: comment_map.keySet()) {
			try {
				go_bin.set_comment(go_bin.get_address(addr, key), ghidra.program.model.listing.CodeUnit.PRE_COMMENT, comment_map.get(key).toString());
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to add file line comment: addr=%s, name=%s, message=%s", gofunc.get_func_addr(), gofunc.get_func_name(), e.getMessage()));
			}
		}
	}

	private void add_file_line_comment_wasm(GolangFunction gofunc, Map<Integer, FileLine> comment_map) {
		TreeMap<Integer, Address> markers = new TreeMap<>(build_wasm_pc_marker_map(gofunc));
		if (markers.isEmpty()) {
			return;
		}
		List<Integer> keys = new ArrayList<>(comment_map.keySet());
		Collections.sort(keys);
		for (int i = 0; i < keys.size(); i++) {
			int key = keys.get(i);
			int next_key = (i + 1 < keys.size()) ? keys.get(i + 1) : Integer.MAX_VALUE;
			Address target = markers.get(key);
			if (target == null) {
				// Go didn't emit a runtime-PC marker at this pseudo-PC. Fall back to the
				// closest marker that still belongs to this pcln entry's range
				// [key, next_key) so we don't bleed the annotation into the next line range.
				Map.Entry<Integer, Address> ceiling = markers.ceilingEntry(key);
				if (ceiling == null || ceiling.getKey() >= next_key) {
					continue;
				}
				target = ceiling.getValue();
			}
			try {
				go_bin.set_comment(target, ghidra.program.model.listing.CodeUnit.PRE_COMMENT, comment_map.get(key).toString());
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to add file line comment: addr=%s, name=%s, message=%s", gofunc.get_func_addr(), gofunc.get_func_name(), e.getMessage()));
			}
		}
	}

	// Go's WASM emits an `i64.const (funcEntry<<16)|pseudoPC; i64.store local_8` pair
	// at the start of each Go-level instruction to update the runtime PC global. By
	// scanning the function body for these constants we recover a mapping from each
	// pcln pseudo-PC value to its actual byte address within the WASM body. Without
	// this, treating the pcln key as a byte offset crams every source-line annotation
	// into the dispatch-chain bytes at the start of the function.
	private Map<Integer, Address> build_wasm_pc_marker_map(GolangFunction gofunc) {
		Map<Integer, Address> map = new HashMap<>();
		Function func = gofunc.get_func();
		if (func == null) {
			return map;
		}
		int func_entry = -1;
		InstructionIterator iter = func.getProgram().getListing().getInstructions(func.getBody(), true);
		while (iter.hasNext()) {
			Instruction inst = iter.next();
			if (!inst.getMnemonicString().equals("i64.const")) {
				continue;
			}
			Object[] objs = inst.getOpObjects(0);
			for (Object o : objs) {
				if (!(o instanceof Scalar)) {
					continue;
				}
				long val = ((Scalar) o).getUnsignedValue();
				int upper = (int) (val >>> 16);
				int lower = (int) (val & 0xFFFF);
				// PC markers have a funcEntry upper word that's well above any plausible
				// numeric constant a function would push (Go's first user funcEntry is
				// 0x1000 in our binaries). Anchor on the first such i64.const we see.
				if (upper < 0x100) {
					continue;
				}
				if (func_entry == -1) {
					func_entry = upper;
				}
				if (upper == func_entry) {
					map.putIfAbsent(lower, inst.getAddress());
				}
			}
		}
		return map;
	}
}
