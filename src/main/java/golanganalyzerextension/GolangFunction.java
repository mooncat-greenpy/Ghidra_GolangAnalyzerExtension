package golanganalyzerextension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

// debug/gosym/pclntab.go
public class GolangFunction extends GolangBinary {
	List<String> file_name_list=null;

	Address info_addr=null;
	Address func_addr=null;
	Function func=null;
	String func_name="";
	List<Parameter> params=null;
	Map<Integer, String> file_line_comment_map=null;

	public GolangFunction(Program program, TaskMonitor monitor, MessageLog log, Address base, Address func_info_addr, List<String> file_name_list, boolean debugmode) {
		super(program, monitor, log, debugmode);

		if(!init_gopclntab(base)) {
			return;
		}
		this.info_addr=func_info_addr;
		this.file_name_list=file_name_list;

		if(!init_func()) {
			return;
		}

		this.ok=true;
	}

	public GolangFunction(FunctionModifier obj, Address func_info_addr) {
		super(obj);

		this.file_name_list=obj.file_name_list;
		this.info_addr=func_info_addr;

		if(!init_func()) {
			return;
		}

		this.ok=true;
	}

	boolean init_func() {
		long entry_addr_value=get_address_value(info_addr, pointer_size);
		func_addr=program.getAddressFactory().getDefaultAddressSpace().getAddress(entry_addr_value);
		func=program.getFunctionManager().getFunctionAt(func_addr);
		if(func==null) {
			CreateFunctionCmd cmd=new CreateFunctionCmd(func_name, func_addr, null, SourceType.ANALYSIS);
			cmd.applyTo(program, monitor);
			func=program.getFunctionManager().getFunctionAt(func_addr);
		}
		if(func==null) {
			append_message(String.format("Failed to get function: %x", entry_addr_value));
			return false;
		}

		if(!init_func_name()) {
			return false;
		}
		if(!init_params()) {
			return false;
		}
		if(!init_file_line_map()) {
			return false;
		}

		return true;
	}

	boolean init_func_name() {
		boolean is_go116=false;
		if(compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		int func_name_offset=(int)get_address_value(get_address(info_addr, pointer_size), 4);
		Address func_name_addr=null;
		if(is_go116) {
			Address func_name_base=get_address(gopclntab_base, get_address_value(get_address(gopclntab_base, 8+pointer_size*2), pointer_size));
			func_name_addr=get_address(func_name_base, func_name_offset);
		}else {
			func_name_addr=get_address(gopclntab_base, func_name_offset);
		}
		if(func_name_addr==null) {
			return false;
		}
		func_name=create_string_data(func_name_addr);
		return true;
	}

	boolean init_params() {
		int args_num=(int)get_address_value(get_address(info_addr, pointer_size+4), 4);

		try {
			params=new ArrayList<>();
			for(int i=0;i<args_num/pointer_size && i<50;i++) {
				DataType data_type=null;
				if(i<func.getParameterCount()) {
					data_type=func.getParameter(i).getDataType();
				}else if(pointer_size==8) {
					data_type=new Undefined8DataType();
				}else {
					data_type=new Undefined4DataType();
				}
				Parameter add_param=new ParameterImpl(String.format("param_%d", i+1), data_type, (i+1)*pointer_size, func.getProgram(), SourceType.USER_DEFINED);
				params.add(add_param);
			}
		}catch(Exception e) {
			append_message(String.format("Failed to set function parameters: %s", e.getMessage()));
			return false;
		}
		return true;
	}

	boolean init_file_line_map() {
		boolean is_go116=false;
		if(compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		file_line_comment_map = new HashMap<>();

		Address pcln_base=null;
		int pcln_offset=(int)get_address_value(get_address(info_addr, pointer_size+5*4), 4);
		if(is_go116) {
			pcln_base=get_address(gopclntab_base, get_address_value(get_address(gopclntab_base, 8+pointer_size*5), pointer_size));
			pcln_base=get_address(pcln_base, pcln_offset);
		}else {
			pcln_base=get_address(gopclntab_base, pcln_offset);
		}

		long line_num=-1;
		int i=0;
		boolean first=true;
		int pc_offset=0;
		while(true) {
			int line_num_add=read_pc_data(get_address(pcln_base, i));
			i+=Integer.toBinaryString(line_num_add).length()/8+1;
			int byte_size=read_pc_data(get_address(pcln_base, i));
			i+=Integer.toBinaryString(byte_size).length()/8+1;
			if(line_num_add==0 && !first) {
				break;
			}

			first=false;
			int key=pc_offset;
			line_num_add=zig_zag_decode(line_num_add);
			line_num+=line_num_add;
			pc_offset+=byte_size*quantum;
			String file_name=pc_to_file_name(pc_offset);
			if(file_name==null) {
				file_name="not found";
			}

			file_line_comment_map.put(key, String.format("%s:%d", file_name, line_num));
		}
		return true;
	}

	String pc_to_file_name(int target_pc_offset) {
		boolean is_go116=false;
		if(compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		Address pcfile_base=null;
		int pcfile_offset=(int)get_address_value(get_address(info_addr, pointer_size+4*4), 4);
		if(is_go116) {
			pcfile_base=get_address(gopclntab_base, get_address_value(get_address(gopclntab_base, 8+pointer_size*5), pointer_size));
			pcfile_base=get_address(pcfile_base, pcfile_offset);
		}else {
			pcfile_base=get_address(gopclntab_base, pcfile_offset);
		}

		long file_no=-1;
		int i=0;
		boolean first=true;
		int pc_offset=0;
		while(true) {
			int file_no_add=read_pc_data(get_address(pcfile_base, i));
			i+=Integer.toBinaryString(file_no_add).length()/8+1;
			int byte_size=read_pc_data(get_address(pcfile_base, i));
			i+=Integer.toBinaryString(byte_size).length()/8+1;
			if(file_no_add==0 && !first) {
				break;
			}
			first=false;
			file_no_add=zig_zag_decode(file_no_add);
			file_no+=file_no_add;
			pc_offset+=byte_size*quantum;

			if(target_pc_offset<=pc_offset) {
				if(is_go116) {
					int cu_offset=(int)get_address_value(get_address(info_addr, pointer_size+4*7), 4);
					Address cutab_base=get_address(gopclntab_base, get_address_value(get_address(gopclntab_base, 8+pointer_size*3), pointer_size));
					if(cutab_base==null) {
						return null;
					}
					long file_no_offset=get_address_value(get_address(cutab_base, (cu_offset+file_no)*4), 4);
					Address file_base=get_address(gopclntab_base, get_address_value(get_address(gopclntab_base, 8+pointer_size*4), pointer_size));
					Address file_name_addr=get_address(file_base, file_no_offset);
					if(file_name_addr==null) {
						return null;
					}
					return create_string_data(file_name_addr);
				}
				if((int)file_no-1<0 || file_name_list.size()<=(int)file_no-1) {
					append_message(String.format("File name list index out of range: %x", (int)file_no-1));
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
		if(addr==null) {
			return 0;
		}
		int value=0;
		for(int i=0, shift=0;;i++, shift+=7) {
			int tmp=0;
			tmp=(int)get_address_value(get_address(addr, i), 1);
			value|=(tmp&0x7f)<<shift;
			if((tmp&0x80)==0) {
				break;
			}
		}
		return value;
	}

	Address get_func_addr() {
		return func_addr;
	}

	Function get_func() {
		return func;
	}

	String get_func_name() {
		return func_name;
	}

	List<Parameter> get_params(){
		return params;
	}

	Map<Integer, String> get_file_line_comment_map(){
		return file_line_comment_map;
	}
}
