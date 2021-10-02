package golanganalyzerextension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;

import ghidra.app.cmd.function.CreateFunctionCmd;
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
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;

// debug/gosym/pclntab.go
public class GolangFunction extends GolangBinary {
	List<String> file_name_list=null;

	Address info_addr=null;
	long func_size=0;
	Map<Integer, Long> frame_map=null;

	Address func_addr=null;
	Function func=null;
	String func_name="";
	List<Parameter> params=null;
	Map<Integer, String> file_line_comment_map=null;

	public GolangFunction(FunctionModifier obj, Address func_info_addr, long func_size) {
		super(obj);

		this.file_name_list=obj.file_name_list;
		this.info_addr=func_info_addr;
		this.func_size=func_size;
		this.frame_map = new TreeMap<>();

		if(!init_func()) {
			return;
		}

		this.ok=true;
	}

	public GolangFunction(FunctionModifier obj, Function func, String func_name, List<Parameter> params) {
		super(obj);

		this.func_addr=func.getEntryPoint();
		this.func=func;
		this.func_name=func_name;
		this.params=params;
		this.file_line_comment_map=new HashMap<>();
		this.frame_map = new TreeMap<>();

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

	Map<Integer, String> reg_arg_map= new HashMap<>(){
		{
			put(1, "RAX");
			put(2, "RBX");
			put(3, "RCX");
			put(4, "RDI");
			put(5, "RSI");
			put(6, "R8");
			put(7, "R9");
			put(8, "R10");
			put(9, "R11");
		}
	};
	String get_reg_arg_name(int arg_count, int arg_num) {
		if(arg_num>=reg_arg_map.size()) {
			arg_count-=arg_num-reg_arg_map.size();
		}
		return reg_arg_map.get(arg_count);
	}

	boolean check_inst_reg_arg(Instruction inst, int arg_num) {
		if(compare_go_version("go1.17beta1")>0) {
			return false;
		}
		String mnemonic=inst.getMnemonicString();
		if(!mnemonic.equals("MOV") || inst.getNumOperands()<2) {
			return false;
		}

		Object op1[]=inst.getOpObjects(0);
		Object op2[]=inst.getOpObjects(1);
		if(op1.length<2 || op2.length<1) {
			return false;
		}

		if(!op1[0].toString().equals("RSP") ||
				!(op1[1] instanceof Scalar)) {
			return false;
		}
		long frame_size=get_frame((int)(inst.getAddress().getOffset()-func_addr.getOffset()));
		int arg_count=(Integer.decode(op1[1].toString())-(int)frame_size-pointer_size)/pointer_size+1;
		String reg_arg_name=get_reg_arg_name(arg_count, arg_num);
		if(reg_arg_name==null) {
			return false;
		}
		if(reg_arg_name.equals(op2[0].toString())) {
			return true;
		}
		return false;
	}

	enum REG_FLAG {
		NOT_FOUND,
		READ,
		WRITE,
	}
	boolean check_inst_builtin_reg_arg(Instruction inst, REG_FLAG reg_flag[], List<Register> reg_arg) {
		if(inst.getMnemonicString().equals("RET") || inst.getMnemonicString().equals("JMP")) {
			return true;
		}
		Object op_input[]=inst.getInputObjects();
		Object op_output[]=inst.getResultObjects();

		for(int j=0;j<op_input.length;j++) {
			if(!(op_input[j] instanceof Register)) {
				continue;
			}
			Register reg=(Register)op_input[j];
			int reg_read_index=-1;
			if(compare_register(reg, program.getRegister("AX"))) {
				reg_read_index=0;
			}else if(compare_register(reg, program.getRegister("BX"))) {
				reg_read_index=1;
			}else if(compare_register(reg, program.getRegister("CX"))) {
				reg_read_index=2;
			}else if(compare_register(reg, program.getRegister("DX"))) {
				reg_read_index=3;
			}else if(compare_register(reg, program.getRegister("DI"))) {
				reg_read_index=4;
			}else if(compare_register(reg, program.getRegister("SI"))) {
				reg_read_index=5;
			}else if(compare_register(reg, program.getRegister("BP"))) {
				reg_read_index=6;
			}

			if(reg_read_index<0 || reg_flag.length<=reg_read_index) {
				continue;
			}
			if(inst.getMnemonicString().equals("XOR") &&
					(inst.getNumOperands()==2 && inst.getOpObjects(0).length>0 && inst.getOpObjects(1).length>0 &&
					inst.getOpObjects(0)[0].toString().equals(inst.getOpObjects(1)[0].toString()))) {
				continue;
			}
			if(inst.getMnemonicString().equals("PUSH") || inst.getMnemonicString().equals("XCHG")) {
				continue;
			}
			if(reg_flag[reg_read_index].equals(REG_FLAG.NOT_FOUND)) {
				reg_flag[reg_read_index]=REG_FLAG.READ;
				reg_arg.add(reg);
			}
		}
		for(int j=0;j<op_output.length;j++) {
			if(!(op_output[j] instanceof Register)) {
				continue;
			}
			Register reg=(Register)op_output[j];
			int reg_write_index=-1;
			if(compare_register(reg, program.getRegister("AX"))) {
				reg_write_index=0;
			}else if(compare_register(reg, program.getRegister("BX"))) {
				reg_write_index=1;
			}else if(compare_register(reg, program.getRegister("CX"))) {
				reg_write_index=2;
			}else if(compare_register(reg, program.getRegister("DX"))) {
				reg_write_index=3;
			}else if(compare_register(reg, program.getRegister("DI"))) {
				reg_write_index=4;
			}else if(compare_register(reg, program.getRegister("SI"))) {
				reg_write_index=5;
			}else if(compare_register(reg, program.getRegister("BP"))) {
				reg_write_index=6;
			}

			if(reg_write_index<0 || reg_flag.length<=reg_write_index) {
				continue;
			}
			if(inst.getMnemonicString().equals("XCHG")) {
				reg_flag[reg_write_index]=REG_FLAG.WRITE;
			}
			if(reg_flag[reg_write_index].equals(REG_FLAG.NOT_FOUND)) {
				reg_flag[reg_write_index]=REG_FLAG.WRITE;
			}
		}
		return false;
	}

	boolean init_params() {
		int arg_size=(int)get_address_value(get_address(info_addr, pointer_size+4), 4);
		int args_num=arg_size/pointer_size+(arg_size%pointer_size==0?0:1);

		init_frame_map();

		boolean is_reg_arg=false;
		REG_FLAG builtin_reg_flag[]= {REG_FLAG.NOT_FOUND, REG_FLAG.NOT_FOUND, REG_FLAG.NOT_FOUND, REG_FLAG.NOT_FOUND, REG_FLAG.NOT_FOUND, REG_FLAG.NOT_FOUND, REG_FLAG.NOT_FOUND};
		List<Register> builtin_reg_arg=new ArrayList<>();
		boolean is_checked_builtin_reg=false;
		Instruction inst=program_listing.getInstructionAt(func_addr);
		while(inst!=null && inst.getAddress().getOffset()<func_addr.getOffset()+func_size) {
			if(!is_reg_arg) {
				is_reg_arg=check_inst_reg_arg(inst, args_num);
			}
			if(!is_checked_builtin_reg) {
				is_checked_builtin_reg=check_inst_builtin_reg_arg(inst, builtin_reg_flag, builtin_reg_arg);
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
				}else {
					data_type=func.getParameter(i).getDataType();
				}
				Register reg=null;
				if(is_reg_arg) {
					reg=program.getRegister(get_reg_arg_name(i+1, args_num));
				}else if(is_builtin_reg) {
					reg=builtin_reg_arg.get(i);
				}
				Parameter add_param=null;
				if(reg==null) {
					add_param=new ParameterImpl(String.format("param_%d", i+1), data_type, (i+1)*pointer_size, func.getProgram(), SourceType.USER_DEFINED);
				}else {
					add_param=new ParameterImpl(String.format("param_%d", i+1), data_type, reg, func.getProgram(), SourceType.USER_DEFINED);
				}
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

	boolean init_frame_map() {
		boolean is_go116=false;
		if(compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		Address pcln_base=null;
		int pcln_offset=(int)get_address_value(get_address(info_addr, pointer_size+3*4), 4);
		if(is_go116) {
			pcln_base=get_address(gopclntab_base, get_address_value(get_address(gopclntab_base, 8+pointer_size*5), pointer_size));
			pcln_base=get_address(pcln_base, pcln_offset);
		}else {
			pcln_base=get_address(gopclntab_base, pcln_offset);
		}

		long frame_size=-1;
		int i=0;
		boolean first=true;
		int pc_offset=0;
		while(true) {
			int frame_size_add=read_pc_data(get_address(pcln_base, i));
			i+=Integer.toBinaryString(frame_size_add).length()/8+1;
			int byte_size=read_pc_data(get_address(pcln_base, i));
			i+=Integer.toBinaryString(byte_size).length()/8+1;
			if(frame_size_add==0 && !first) {
				break;
			}

			first=false;
			frame_size_add=zig_zag_decode(frame_size_add);
			frame_size+=frame_size_add;
			pc_offset+=byte_size*quantum;

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
