package golanganalyzerextension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Undefined1DataType;
import ghidra.program.model.data.Undefined2DataType;
import ghidra.program.model.data.Undefined3DataType;
import ghidra.program.model.data.Undefined4DataType;
import ghidra.program.model.data.Undefined5DataType;
import ghidra.program.model.data.Undefined6DataType;
import ghidra.program.model.data.Undefined7DataType;
import ghidra.program.model.data.Undefined8DataType;
import ghidra.program.model.data.UnsignedInteger16DataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;


// debug/gosym/pclntab.go
public class GolangFunction {
	GolangBinary go_bin=null;

	List<String> file_name_list=null;
	boolean disasm_option=false;
	boolean extended_option=false;

	Address info_addr=null;
	long func_size=0;
	Map<Integer, Long> frame_map=null;

	Address func_addr=null;
	Function func=null;
	String func_name="";
	List<Parameter> params=null;
	Map<Integer, String> file_line_comment_map=null;

	boolean ok=false;

	public GolangFunction(GolangBinary go_bin, Address func_info_addr, long func_size, List<String> file_name_list, boolean disasm_option, boolean extended_option) {
		this.go_bin=go_bin;

		this.file_name_list=file_name_list;
		this.disasm_option=disasm_option;
		this.extended_option=extended_option;
		this.info_addr=func_info_addr;
		this.func_size=func_size;
		this.frame_map = new TreeMap<>();

		if(!init_func()) {
			return;
		}

		this.ok=true;
	}

	public GolangFunction(GolangBinary go_bin, Function func, boolean disasm_option, boolean extended_option) {
		this.go_bin=go_bin;
		this.disasm_option=disasm_option;
		this.extended_option=extended_option;

		this.func_addr=func.getEntryPoint();
		this.func=func;
		this.file_line_comment_map=new HashMap<>();
		this.frame_map = new TreeMap<>();

		if(check_memcopy()) {
			this.ok=true;
			return;
		}
		if(check_memset()) {
			this.ok=true;
			return;
		}
		this.ok=false;
	}

	boolean is_ok() {
		return ok;
	}

	boolean init_func() {
		long entry_addr_value=go_bin.get_address_value(info_addr, go_bin.get_pointer_size());
		func_addr=go_bin.get_address(entry_addr_value);
		if(disasm_option) {
			go_bin.disassemble(func_addr, func_size);
		}
		func=go_bin.get_function(func_addr);
		if(func==null) {
			go_bin.create_function(func_name, func_addr);
			func=go_bin.get_function(func_addr);
		}
		if(func==null) {
			Logger.append_message(String.format("Failed to get function: %x", entry_addr_value));
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
		if(go_bin.compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address gopclntab_base=go_bin.get_gopclntab_base();
		int func_name_offset=(int)go_bin.get_address_value(info_addr, pointer_size, 4);
		Address func_name_addr=null;
		if(is_go116) {
			Address func_name_base=go_bin.get_address(gopclntab_base, go_bin.get_address_value(gopclntab_base, 8+pointer_size*2, pointer_size));
			func_name_addr=go_bin.get_address(func_name_base, func_name_offset);
		}else {
			func_name_addr=go_bin.get_address(gopclntab_base, func_name_offset);
		}
		if(func_name_addr==null) {
			return false;
		}
		func_name=go_bin.create_string_data(func_name_addr);
		return true;
	}

	enum REG_FLAG {
		READ,
		WRITE,
	}

	boolean check_inst_builtin_reg_arg(Instruction inst, Map<Register, REG_FLAG> builtin_reg_state, List<Register> reg_arg) {
		return false;
	}

	String get_reg_arg_name(int arg_count) {
		return "";
	}

	boolean check_inst_reg_arg(Instruction inst, Map<Register, REG_FLAG> builtin_reg_state) {
		return false;
	}

	boolean init_params() {
		int pointer_size=go_bin.get_pointer_size();
		int arg_size=(int)go_bin.get_address_value(info_addr, pointer_size+4, 4);
		int args_num=arg_size/pointer_size+(arg_size%pointer_size==0?0:1);

		init_frame_map();

		boolean is_reg_arg=false;
		Map<Register, REG_FLAG> builtin_reg_state=new HashMap<>();
		List<Register> builtin_reg_arg=new ArrayList<>();
		boolean is_checked_builtin_reg=false;
		Instruction inst=go_bin.get_instruction(func_addr);
		while(inst!=null && inst.getAddress().getOffset()<func_addr.getOffset()+func_size) {
			if(extended_option && !is_checked_builtin_reg) {
				is_checked_builtin_reg=check_inst_builtin_reg_arg(inst, builtin_reg_state, builtin_reg_arg);
			}
			if(!is_reg_arg) {
				is_reg_arg=check_inst_reg_arg(inst, builtin_reg_state);
			}
			inst=inst.getNext();
		}

		boolean is_builtin_reg=false;
		if(args_num==0 && builtin_reg_arg.size()>=2 && !is_reg_arg) {
			is_builtin_reg=true;
			args_num=builtin_reg_arg.size();
		}

		try {
			params=new ArrayList<>();
			int stack_count=0;
			for(int i=0;i<args_num && i<50;i++) {
				DataType data_type=null;
				int size=pointer_size;
				if(i==args_num-1 && arg_size%pointer_size>0) {
					size=arg_size%pointer_size;
				}else if(is_builtin_reg && !is_reg_arg) {
					size=builtin_reg_arg.get(i).getBitLength()/8;
				}
				if(size==8) {
					data_type=new Undefined8DataType();
				}else if(size==7) {
					data_type=new Undefined7DataType();
				}else if(size==6) {
					data_type=new Undefined6DataType();
				}else if(size==5) {
					data_type=new Undefined5DataType();
				}else if(size==4) {
					data_type=new Undefined4DataType();
				}else if(size==3) {
					data_type=new Undefined3DataType();
				}else if(size==2) {
					data_type=new Undefined2DataType();
				}else if(size==1) {
					data_type=new Undefined1DataType();
				}else if(size==16) {
					data_type=new UnsignedInteger16DataType();
				}else {
					data_type=new Undefined8DataType();
				}
				Register reg=null;
				if(is_reg_arg) {
					reg=go_bin.get_register(get_reg_arg_name(i));
				}else if(is_builtin_reg) {
					reg=builtin_reg_arg.get(i);
				}
				Parameter add_param=null;
				if(reg==null) {
					add_param=new ParameterImpl(String.format("param_%d", i+1), data_type, (stack_count+1)*pointer_size, func.getProgram(), SourceType.USER_DEFINED);
					stack_count++;
				}else {
					add_param=new ParameterImpl(String.format("param_%d", i+1), data_type, reg, func.getProgram(), SourceType.USER_DEFINED);
				}
				params.add(add_param);
			}
		}catch(Exception e) {
			Logger.append_message(String.format("Failed to set function parameters: %s", e.getMessage()));
			return false;
		}
		return true;
	}

	boolean check_memcopy() {
		return false;
	}

	boolean check_memset() {
		return false;
	}

	boolean init_file_line_map() {
		boolean is_go116=false;
		if(go_bin.compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		file_line_comment_map = new HashMap<>();

		int pointer_size=go_bin.get_pointer_size();
		Address gopclntab_base=go_bin.get_gopclntab_base();
		Address pcln_base=null;
		int pcln_offset=(int)go_bin.get_address_value(info_addr, pointer_size+5*4, 4);
		if(is_go116) {
			pcln_base=go_bin.get_address(gopclntab_base, go_bin.get_address_value(gopclntab_base, 8+pointer_size*5, pointer_size));
			pcln_base=go_bin.get_address(pcln_base, pcln_offset);
		}else {
			pcln_base=go_bin.get_address(gopclntab_base, pcln_offset);
		}

		long line_num=-1;
		int i=0;
		boolean first=true;
		int pc_offset=0;
		while(true) {
			int line_num_add=read_pc_data(go_bin.get_address(pcln_base, i));
			i+=Integer.toBinaryString(line_num_add).length()/8+1;
			int byte_size=read_pc_data(go_bin.get_address(pcln_base, i));
			i+=Integer.toBinaryString(byte_size).length()/8+1;
			if(line_num_add==0 && !first) {
				break;
			}

			first=false;
			int key=pc_offset;
			line_num_add=zig_zag_decode(line_num_add);
			line_num+=line_num_add;
			pc_offset+=byte_size*go_bin.get_quantum();
			String file_name=pc_to_file_name(pc_offset);
			if(file_name==null) {
				file_name="not found";
			}

			file_line_comment_map.put(key, String.format("%s:%d", file_name, line_num));
		}
		return true;
	}

	boolean init_frame_map() {
		boolean is_go116=false;
		if(go_bin.compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address gopclntab_base=go_bin.get_gopclntab_base();
		Address pcln_base=null;
		int pcln_offset=(int)go_bin.get_address_value(info_addr, pointer_size+3*4, 4);
		if(is_go116) {
			pcln_base=go_bin.get_address(gopclntab_base, go_bin.get_address_value(gopclntab_base, 8+pointer_size*5, pointer_size));
			pcln_base=go_bin.get_address(pcln_base, pcln_offset);
		}else {
			pcln_base=go_bin.get_address(gopclntab_base, pcln_offset);
		}

		long frame_size=-1;
		int i=0;
		boolean first=true;
		int pc_offset=0;
		while(true) {
			int frame_size_add=read_pc_data(go_bin.get_address(pcln_base, i));
			i+=Integer.toBinaryString(frame_size_add).length()/8+1;
			int byte_size=read_pc_data(go_bin.get_address(pcln_base, i));
			i+=Integer.toBinaryString(byte_size).length()/8+1;
			if(frame_size_add==0 && !first) {
				break;
			}

			first=false;
			frame_size_add=zig_zag_decode(frame_size_add);
			frame_size+=frame_size_add;
			pc_offset+=byte_size*go_bin.get_quantum();

			frame_map.put(pc_offset, frame_size);
		}
		return true;
	}

	long get_frame(int pc_offset) {
		long frame_size=0;
		for(int i : frame_map.keySet()) {
			frame_size=frame_map.get(i);
			if(pc_offset<i) {
				break;
			}
		}
		return frame_size;
	}

	String pc_to_file_name(int target_pc_offset) {
		boolean is_go116=false;
		if(go_bin.compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address gopclntab_base=go_bin.get_gopclntab_base();
		Address pcfile_base=null;
		int pcfile_offset=(int)go_bin.get_address_value(info_addr, pointer_size+4*4, 4);
		if(is_go116) {
			pcfile_base=go_bin.get_address(gopclntab_base, go_bin.get_address_value(gopclntab_base, 8+pointer_size*5, pointer_size));
			pcfile_base=go_bin.get_address(pcfile_base, pcfile_offset);
		}else {
			pcfile_base=go_bin.get_address(gopclntab_base, pcfile_offset);
		}

		long file_no=-1;
		int i=0;
		boolean first=true;
		int pc_offset=0;
		while(true) {
			int file_no_add=read_pc_data(go_bin.get_address(pcfile_base, i));
			i+=Integer.toBinaryString(file_no_add).length()/8+1;
			int byte_size=read_pc_data(go_bin.get_address(pcfile_base, i));
			i+=Integer.toBinaryString(byte_size).length()/8+1;
			if(file_no_add==0 && !first) {
				break;
			}
			first=false;
			file_no_add=zig_zag_decode(file_no_add);
			file_no+=file_no_add;
			pc_offset+=byte_size*go_bin.get_quantum();

			if(target_pc_offset<=pc_offset) {
				if(is_go116) {
					int cu_offset=(int)go_bin.get_address_value(info_addr, pointer_size+4*7, 4);
					Address cutab_base=go_bin.get_address(gopclntab_base, go_bin.get_address_value(gopclntab_base, 8+pointer_size*3, pointer_size));
					if(cutab_base==null) {
						return null;
					}
					long file_no_offset=go_bin.get_address_value(cutab_base, (cu_offset+file_no)*4, 4);
					Address file_base=go_bin.get_address(gopclntab_base, go_bin.get_address_value(gopclntab_base, 8+pointer_size*4, pointer_size));
					Address file_name_addr=go_bin.get_address(file_base, file_no_offset);
					if(file_name_addr==null) {
						return null;
					}
					return go_bin.create_string_data(file_name_addr);
				}
				if((int)file_no-1<0 || file_name_list.size()<=(int)file_no-1) {
					Logger.append_message(String.format("File name list index out of range: %x", (int)file_no-1));
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
			tmp=(int)go_bin.get_address_value(addr, i, 1);
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
