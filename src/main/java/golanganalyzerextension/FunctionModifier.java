package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.task.TaskMonitor;


public class FunctionModifier {
	Program program=null;
	TaskMonitor monitor=null;
	MessageLog log=null;
	Listing program_listing=null;
	Memory memory=null;
	Address base=null;

	List<String> file_name_list=null;
	int quantum=0;
	int pointer_size=0;
	int func_num=0;

	public FunctionModifier(Program program, TaskMonitor monitor, MessageLog log) {
		this.program=program;
		this.monitor=monitor;
		this.log=log;
		this.program_listing=program.getListing();
		this.memory=program.getMemory();

		init_gopclntab();
	}

	void init_gopclntab() {
		this.base=get_gopclntab();

		// magic, two zero bytes
		this.quantum=(int)get_address_value(base.add(6), 1);      // arch(x86=1, ?=2, arm=4)
		this.pointer_size=(int)get_address_value(base.add(7), 1); // pointer size
		this.func_num=(int)get_address_value(base.add(8), 4);     // number of func

		this.file_name_list=get_file_list();
	}

	void modify() {
		Address func_list_base=base.add(8+pointer_size);
		for(int i=0; i<func_num; i++) {
			long func_addr_value=get_address_value(func_list_base.add(i*pointer_size*2), pointer_size);
			long func_info_offset=get_address_value(func_list_base.add(i*pointer_size*2+pointer_size), pointer_size);

			analyze_func(func_addr_value, func_info_offset);
		}
	}

	boolean analyze_func(long func_addr_value, long func_info_offset) {
		long func_entry_value=get_address_value(base.add(func_info_offset), pointer_size);
		int func_name_offset=(int)get_address_value(base.add(func_info_offset+pointer_size), 4);
		int args=(int)get_address_value(base.add(func_info_offset+pointer_size+4), 4);

		if(func_addr_value!=func_entry_value) {
			log.appendMsg(String.format("Failed wrong func addr %x %x", func_addr_value, func_entry_value));
			return false;
		}

		String func_name="not found";
		try {
			func_name=create_string_data(base.add(func_name_offset));
		}catch(CodeUnitInsertionException e) {
			log.appendMsg(String.format("Failed create file name: %s", e.getMessage()));
		}

		rename_func(func_addr_value, func_name);
		modify_func_param(func_addr_value, args);
		add_func_comment(func_addr_value, func_info_offset);

		return true;
	}

	void rename_func(long func_addr_value, String func_name) {
		Address func_addr=program.getAddressFactory().getDefaultAddressSpace().getAddress(func_addr_value);
		Function func=program.getFunctionManager().getFunctionAt(func_addr);
		if(func==null) {
			CreateFunctionCmd cmd=new CreateFunctionCmd(func_name, func_addr, null, SourceType.ANALYSIS);
			cmd.applyTo(program, monitor);
			return;
		}else if(func.getName().equals(func_name)) {
			return;
		}
		try {
			func.setName(func_name, SourceType.ANALYSIS);
		}catch(Exception e) {
			log.appendMsg("Failed set function name");
		}
	}

	void modify_func_param(long func_addr_value, int args_num) {
		Address func_addr=program.getAddressFactory().getDefaultAddressSpace().getAddress(func_addr_value);
		Function func=program.getFunctionManager().getFunctionAt(func_addr);
		if(func==null) {
			return;
		}
		if(func.getParameterCount()==args_num/pointer_size) {
			return;
		}

		try {
			List<Parameter> new_params=new ArrayList<>();
			for(int i=0;i<args_num/pointer_size;i++) {
				DataType data_type=null;
				if(i<func.getParameterCount()) {
					data_type=func.getParameter(i).getDataType();
				}else if(pointer_size==8) {
					data_type=new Undefined8DataType();
				}else {
					data_type=new Undefined4DataType();
				}
				Parameter param=new ParameterImpl(String.format("param_%d", i+1), data_type, (i+1)*pointer_size, func.getProgram(), SourceType.USER_DEFINED);
				new_params.add(param);
			}

			func.updateFunction(null, null, new_params, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
		}catch(Exception e) {
			log.appendMsg(String.format("Failed set function parameter"));
		}
	}

	void add_func_comment(long func_addr_value, long func_info_offset) {
		int pcln_offset=(int)get_address_value(base.add(func_info_offset+pointer_size+5*4), 4);
		long line_num=-1;
		Address comment_addr=program.getAddressFactory().getDefaultAddressSpace().getAddress(func_addr_value);
		int j=0;
		boolean first=true;
		int pc_offset=0;
		while(true) {
			int line_num_add=read_pc_data(base.add(pcln_offset+j));
			j+=Integer.toBinaryString(line_num_add).length()/8+1;
			int byte_size=read_pc_data(base.add(pcln_offset+j));
			j+=Integer.toBinaryString(byte_size).length()/8+1;
			if(line_num_add==0 && !first) {
				break;
			}
			first=false;
			line_num_add=zig_zag_decode(line_num_add);
			line_num+=line_num_add;
			pc_offset+=byte_size*quantum;
			String file_name=pc_to_file_name(func_info_offset, pc_offset);
			if(file_name==null) {
				file_name="not found";
			}
			Listing listing=program.getListing();
			listing.setComment(comment_addr, ghidra.program.model.listing.CodeUnit.PRE_COMMENT, String.format("%s:%d", file_name, line_num));

			comment_addr=comment_addr.add(byte_size);
		}
	}

	List<String> get_file_list() {
		Address func_list_base=base.add(8+pointer_size);
		file_name_list=new ArrayList<>();
		try {
			long file_name_table_offset=get_address_value(func_list_base.add(func_num*pointer_size*2+pointer_size), pointer_size);
			Address file_name_table=base.add(file_name_table_offset);
			long file_name_table_size=get_address_value(file_name_table, 4);
			for(int i=1;i<file_name_table_size;i++) {
				long file_name_offset=get_address_value(file_name_table.add(4*i),4);
				String file_name=create_string_data(base.add(file_name_offset));
				file_name_list.add(file_name);
			}
		}catch(CodeUnitInsertionException e) {
			log.appendMsg(String.format("Failed get_file_list: %s", e.getMessage()));
		}
		return file_name_list;
	}

	String create_string_data(Address address) throws CodeUnitInsertionException {
		Data func_name_data=program_listing.getDefinedDataAt(address);
		if(func_name_data==null) {
			func_name_data=program_listing.createData(address, new StringDataType());
		}else if(!func_name_data.getDataType().isEquivalent((new StringDataType()))) {
			return null;
		}
		return (String)func_name_data.getValue();
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

		byte magic[]= {(byte)0xfb,(byte)0xff,(byte)0xff,(byte)0xff};
		Address gopclntab_base=null;
		while(true) {
			gopclntab_base=memory.findBytes(gopclntab_base, magic, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff}, true, monitor);
			if(gopclntab_base==null) {
				break;
			}

			Address func_list_base=gopclntab_base.add(8+pointer_size);
			long func_addr_value=get_address_value(func_list_base.add(0), pointer_size);
			long func_info_offset=get_address_value(func_list_base.add(pointer_size), pointer_size);
			long func_entry_value=get_address_value(base.add(func_info_offset), pointer_size);
			if(func_addr_value==func_entry_value)
			{
				break;
			}
			gopclntab_base=gopclntab_base.add(4);
		}
		return gopclntab_base;
	}

	String pc_to_file_name(long func_info_offset, int target_pc_offset) {
		int pcfile_offset=0;
		pcfile_offset=(int)get_address_value(base.add(func_info_offset+pointer_size+4*4), 4);

		int pc_offset=0;
		long file_no=-1;
		int i=0;
		boolean first=true;
		while(true) {
			int file_no_add=read_pc_data(base.add(pcfile_offset+i));
			i+=Integer.toBinaryString(file_no_add).length()/8+1;
			int byte_size=read_pc_data(base.add(pcfile_offset+i));
			i+=Integer.toBinaryString(byte_size).length()/8+1;
			if(file_no_add==0 && !first) {
				break;
			}
			first=false;
			file_no_add=zig_zag_decode(file_no_add);
			file_no+=file_no_add;
			pc_offset+=byte_size*quantum;

			if(target_pc_offset<=pc_offset) {
				if((int)file_no-1<0 || file_name_list.size()<=(int)file_no-1) {
					return null;
				}
				return file_name_list.get((int)file_no-1);
			}
		}
		return null;
	}

	int zig_zag_decode(int value) {
		if((value&1)!=0) {
			value=(value>>1)+1;
			value*=-1;
		}else {
			value>>=1;
		}
		return value;
	}

	int read_pc_data(Address addr) {
		int value=0;
		for(int i=0, shift=0;;i++, shift+=7) {
			int tmp=0;
			tmp=(int)get_address_value(addr.add(i), 1);
			value|=(tmp&0x7f)<<shift;
			if((tmp&0x80)==0) {
				break;
			}
		}
		return value;
	}

	long get_address_value(Address address, int size) {
		try {
			if(size==8) {
				return memory.getLong(address);
			}else if(size==4) {
				return memory.getInt(address);
			}
			return memory.getByte(address)&0xff;
		}catch(MemoryAccessException e) {
			log.appendMsg(String.format("Failed get address value: %s", e.getMessage()));
		}
		return 0;
	}
}
