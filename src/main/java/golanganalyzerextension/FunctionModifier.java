package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.task.TaskMonitor;


public class FunctionModifier extends GolangBinary {
	Address base=null;
	int magic=0;
	int quantum=0;
	int pointer_size=0;
	int func_num=0;
	List<GolangFunction> gofunc_list=null;
	List<String> file_name_list=null;

	public FunctionModifier(Program program, TaskMonitor monitor, MessageLog log) {
		super(program, monitor, log);

		init_gopclntab();
		init_functions();
	}

	void init_gopclntab() {
		this.base=get_gopclntab();
		if(this.base==null) {
			log.appendMsg("Failed get gopclntab");
			return;
		}

		this.magic=(int)get_address_value(base, 4);               // magic
		                                                          // two zero bytes
		this.quantum=(int)get_address_value(base.add(6), 1);      // arch(x86=1, ?=2, arm=4)
		this.pointer_size=(int)get_address_value(base.add(7), 1); // pointer size
		this.func_num=(int)get_address_value(base.add(8), 4);     // number of func

		this.file_name_list=get_file_list();
	}

	void init_functions() {
		if(base==null) {
			log.appendMsg("Error base address is null");
			return;
		}

		gofunc_list=new ArrayList<>();
		Address func_list_base=base.add(8+pointer_size);
		for(int i=0; i<func_num; i++) {
			long func_addr_value=get_address_value(func_list_base.add(i*pointer_size*2), pointer_size);
			long func_info_offset=get_address_value(func_list_base.add(i*pointer_size*2+pointer_size), pointer_size);
			long func_entry_value=get_address_value(base.add(func_info_offset), pointer_size);
			if(func_addr_value!=func_entry_value)
			{
				log.appendMsg(String.format("Failed wrong func addr %x %x", func_addr_value, func_entry_value));
				continue;
			}

			GolangFunction gofunc=new GolangFunction(program, monitor, log, base, func_info_offset, file_name_list);
			gofunc_list.add(gofunc);
		}
	}

	void modify() {
		if(base==null) {
			log.appendMsg("Error base address is null");
			return;
		}

		for(GolangFunction gofunc: gofunc_list) {
		    rename_func(gofunc);
		    modify_func_param(gofunc);
		    add_func_comment(gofunc);
		}
	}

	void rename_func(GolangFunction gofunc) {
		Function func=gofunc.get_func();
		String func_name=gofunc.get_func_name();

		if(func.getName().equals(func_name)) {
			return;
		}
		try {
			func.setName(func_name, SourceType.ANALYSIS);
		}catch(Exception e) {
			log.appendMsg(String.format("Failed set function name: %s", e.getMessage()));
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
		}catch(Exception e) {
			log.appendMsg(String.format("Failed set function parameter: %s", e.getMessage()));
		}
	}

	void add_func_comment(GolangFunction gofunc) {
		Address addr=gofunc.get_func_addr();
		Map<Integer, String> comment_map=gofunc.get_file_line_comment_map();
		Listing listing=program.getListing();

		for(Integer key: comment_map.keySet()) {
			listing.setComment(addr.add(key), ghidra.program.model.listing.CodeUnit.PRE_COMMENT, comment_map.get(key));
		}
	}

	List<String> get_file_list() {
		List<String> file_list=new ArrayList<>();
		Address func_list_base=base.add(8+pointer_size);
		if(func_list_base==null) {
			return file_list;
		}
		try {
			long file_name_table_offset=get_address_value(func_list_base.add(func_num*pointer_size*2+pointer_size), pointer_size);
			Address file_name_table=base.add(file_name_table_offset);
			if(file_name_table==null) {
				return file_list;
			}
			long file_name_table_size=get_address_value(file_name_table, 4);
			for(int i=1;i<file_name_table_size;i++) {
				long file_name_offset=get_address_value(file_name_table.add(4*i),4);
				String file_name=create_string_data(base.add(file_name_offset));
				file_list.add(file_name);
			}
		}catch(CodeUnitInsertionException e) {
			log.appendMsg(String.format("Failed get_file_list: %s", e.getMessage()));
		}
		return file_list;
	}

	Address get_gopclntab() {
		MemoryBlock gopclntab_section=null;
		for (MemoryBlock mb : memory.getBlocks()) {
			if(mb.getName().equals(".gopclntab")) {
				gopclntab_section=mb;
			}
		}
		if(gopclntab_section!=null) {
			return gopclntab_section.getStart();
		}

		byte go12_magic[]= {(byte)0xfb,(byte)0xff,(byte)0xff,(byte)0xff};
		Address gopclntab_base=null;
		while(true) {
			gopclntab_base=memory.findBytes(gopclntab_base, go12_magic, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff}, true, monitor);
			if(gopclntab_base==null) {
				break;
			}

			int size=(int)get_address_value(gopclntab_base.add(7), 1); // pointer size

			Address func_list_base=gopclntab_base.add(8+size);
			if(func_list_base==null) {
				gopclntab_base=gopclntab_base.add(4);
			}
			long func_addr_value=get_address_value(func_list_base.add(0), size);
			long func_info_offset=get_address_value(func_list_base.add(size), size);
			long func_entry_value=get_address_value(gopclntab_base.add(func_info_offset), size);
			if(func_addr_value==func_entry_value)
			{
				break;
			}
			gopclntab_base=gopclntab_base.add(4);
		}

		return gopclntab_base;
	}
}
