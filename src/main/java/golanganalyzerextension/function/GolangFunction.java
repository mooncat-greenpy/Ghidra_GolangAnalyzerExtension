package golanganalyzerextension.function;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.TreeMap;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
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
import ghidra.program.model.listing.ReturnParameterImpl;
import ghidra.program.model.listing.VariableStorage;
import ghidra.program.model.pcode.Varnode;
import ghidra.program.model.symbol.SourceType;
import golanganalyzerextension.datatype.GolangDatatypeRecord;
import golanganalyzerextension.datatype.UncommonType.UncommonMethod;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;
import golanganalyzerextension.version.GolangVersion;


// debug/gosym/pclntab.go
public class GolangFunction {
	GolangBinary go_bin;
	GolangAnalyzerExtensionService service;
	List<String> file_name_list;

	boolean disasm_option;

	Address info_addr;
	long func_size;

	Address func_addr;
	Function func;
	String func_name;
	int arg_size;
	List<Parameter> params;
	// Disable in the next release
	// ReturnParameterImpl ret_param;
	Map<Integer, FileLine> file_line_comment_map;
	Map<Integer, Long> frame_map;

	GolangFunction(GolangBinary go_bin, GolangAnalyzerExtensionService service, Address func_info_addr, long func_size, boolean disasm_option) {
		this.go_bin=go_bin;
		this.service=service;
		this.file_name_list=service.get_filename_list();

		this.disasm_option=disasm_option;

		this.info_addr=func_info_addr;
		this.func_size=func_size;

		this.params=new ArrayList<>();
		// Disable in the next release
		// this.ret_param=null;
		this.file_line_comment_map=new HashMap<>();
		this.frame_map = new TreeMap<>();

		if(!init_func()) {
			throw new InvalidBinaryStructureException("Failed to init_func");
		}
	}

	GolangFunction(GolangBinary go_bin, GolangAnalyzerExtensionService service, Function func, boolean disasm_option) {
		this.go_bin=go_bin;
		this.service=service;
		this.file_name_list=new ArrayList<>();

		this.disasm_option=disasm_option;

		this.info_addr=null;
		this.func_size=0;

		this.func_addr=func.getEntryPoint();
		this.func=func;
		this.func_name="not_init";
		this.arg_size=0;
		this.params=new ArrayList<>();
		// Disable in the next release
		// this.ret_param=null;
		this.file_line_comment_map=new HashMap<>();
		this.frame_map = new TreeMap<>();

		if(check_memcopy()) {
			return;
		}
		if(check_memset()) {
			return;
		}
		throw new InvalidBinaryStructureException("Failed to check_memcopy and check_memset");
	}

	public static GolangFunction create_function(GolangBinary go_bin, GolangAnalyzerExtensionService service, Address func_info_addr, long func_size, boolean disasm_option) throws InvalidBinaryStructureException {
		if(go_bin.is_x86()) {
			return new GolangFunctionX86(go_bin, service, func_info_addr, func_size, disasm_option);
		}else if(go_bin.is_arm()) {
			return new GolangFunctionArm(go_bin, service, func_info_addr, func_size, disasm_option);
		}else if(go_bin.is_ppc()) {
			return new GolangFunctionPpc(go_bin, service, func_info_addr, func_size, disasm_option);
		}else if(go_bin.is_riscv()) {
			return new GolangFunctionRiscv(go_bin, service, func_info_addr, func_size, disasm_option);
		}else {
			return new GolangFunction(go_bin, service, func_info_addr, func_size, disasm_option);
		}
	}

	public static GolangFunction create_function_in_function(GolangBinary go_bin, GolangAnalyzerExtensionService service, Function func, boolean disasm_option) throws InvalidBinaryStructureException {
		if(go_bin.is_x86()) {
			return new GolangFunctionX86(go_bin, service, func, disasm_option);
		}else if(go_bin.is_arm()) {
			return new GolangFunctionArm(go_bin, service, func, disasm_option);
		}else if(go_bin.is_ppc()) {
			return new GolangFunctionPpc(go_bin, service, func, disasm_option);
		}else if(go_bin.is_riscv()) {
			return new GolangFunctionRiscv(go_bin, service, func, disasm_option);
		}else {
			return new GolangFunction(go_bin, service, func, disasm_option);
		}
	}

	public Address get_func_addr() {
		return func_addr;
	}

	public Function get_func() {
		return func;
	}

	public long get_func_size() {
		return func_size;
	}

	public String get_func_name() {
		return func_name;
	}

	public int get_arg_size() {
		return arg_size;
	}

	public List<Parameter> get_params(){
		return params;
	}

	// Disable in the next release
	/*public Optional<Parameter> get_ret_param() {
		return Optional.ofNullable(ret_param);
	}*/

	public Map<Integer, FileLine> get_file_line_comment_map(){
		return file_line_comment_map;
	}

	public Map<Integer, Long> get_frame_map() {
		return frame_map;
	}

	boolean check_memcopy() {
		return false;
	}

	boolean check_memset() {
		return false;
	}

	void disassemble() {
		try {
			go_bin.disassemble(func_addr, func_size);
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to disassemble: addr=%s, size=%x", func_addr, func_size));
		}
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

	int get_arg_stack_base() {
		return 0;
	}

	boolean check_inst_reg_arg(Instruction inst, Map<Register, REG_FLAG> builtin_reg_state) {
		return false;
	}

	private boolean init_params() {
		boolean is_go118=false;
		if(go_bin.ge_go_version(GolangVersion.GO_1_18_LOWEST)) {
			is_go118=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		try {
			arg_size=(int)go_bin.get_address_value(info_addr, (is_go118?4:pointer_size)+4, 4);
		} catch (BinaryAccessException e1) {
			Logger.append_message(String.format("Failed to get arg size: info_addr=%s", info_addr));
			return false;
		}
		int args_num=arg_size/pointer_size+(arg_size%pointer_size==0?0:1);

		init_frame_map();

		if(args_num<=0) {
			return true;
		}
		// TODO: Define each function if necessary
		boolean is_reg_arg=false;
		Map<Register, REG_FLAG> builtin_reg_state=new HashMap<>();
		List<Register> builtin_reg_arg=new ArrayList<>();
		boolean is_checked_builtin_reg=false;
		Instruction inst=go_bin.get_instruction(func_addr).orElse(null);
		while(inst!=null && inst.getAddress().getOffset()<func_addr.getOffset()+func_size) {
			if(!is_checked_builtin_reg) {
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
			// Disable in the next release
			// List<Register> ret_regs=new ArrayList<>();
			int stack_base=get_arg_stack_base();
			int stack_count=0;
			for(int i=0;i<args_num && i<50;i++) {
				int size=pointer_size;
				if(i==args_num-1 && arg_size%pointer_size>0) {
					size=arg_size%pointer_size;
				}else if(is_builtin_reg && !is_reg_arg) {
					size=builtin_reg_arg.get(i).getBitLength()/8;
				}
				DataType datatype;
				if(size==8) {
					datatype=new Undefined8DataType();
				}else if(size==7) {
					datatype=new Undefined7DataType();
				}else if(size==6) {
					datatype=new Undefined6DataType();
				}else if(size==5) {
					datatype=new Undefined5DataType();
				}else if(size==4) {
					datatype=new Undefined4DataType();
				}else if(size==3) {
					datatype=new Undefined3DataType();
				}else if(size==2) {
					datatype=new Undefined2DataType();
				}else if(size==1) {
					datatype=new Undefined1DataType();
				}else if(size==16) {
					datatype=new UnsignedInteger16DataType();
				}else {
					datatype=new Undefined8DataType();
				}
				Register reg=null;
				if(is_reg_arg) {
					reg=go_bin.get_register(get_reg_arg_name(i)).orElse(null);
					// Disable in the next release
					/*if(reg!=null) {
						ret_regs.add(reg);
					}*/
				}else if(is_builtin_reg) {
					reg=builtin_reg_arg.get(i);
				}
				Parameter add_param;
				if(reg==null) {
					add_param=new ParameterImpl(String.format("param_%d", i+1), datatype, stack_base+(stack_count+1)*pointer_size, func.getProgram(), SourceType.USER_DEFINED);
					stack_count++;
				}else {
					add_param=new ParameterImpl(String.format("param_%d", i+1), datatype, reg, func.getProgram(), SourceType.USER_DEFINED);
				}
				params.add(add_param);
			}
			// Disable in the next release
			/*if(ret_regs.size() > 0) {
				StructureDataType ret_datatype=new StructureDataType(String.format("ret_datatype_%x", ret_regs.size()), 0);
				for(int i=0; i<ret_regs.size(); i++) {
					ret_datatype.add(go_bin.get_unsigned_numeric_datatype(go_bin.get_pointer_size()), String.format("ret_%x", ret_regs.size()-i), null);
				}
				VariableStorage vs=new VariableStorage(func.getProgram(), (Register[])ret_regs.toArray(new Register[ret_regs.size()]));
				ret_param=new ReturnParameterImpl(ret_datatype, vs, func.getProgram());
			}*/
		}catch(Exception e) {
			Logger.append_message(String.format("Failed to set function parameters: %s", e.getMessage()));
			return false;
		}
		return true;
	}

	public boolean insert_params(String name, int offset, DataType datatype) {
		int size=datatype.getLength();

		int cur_offset=0;
		int idx=0;
		int count=0;
		for(int i=0; i<params.size(); i++) {
			if(cur_offset!=offset) {
				cur_offset+=params.get(i).getLength();
				continue;
			}
			idx=i;
			do {
				cur_offset+=params.get(i).getLength();
				i++;
			} while(cur_offset<offset+size && i<params.size());
			count=i-idx;

			if(cur_offset!=offset+size) {
				return false;
			}
			break;
		}
		if(count==0) {
			return false;
		}

		List<Varnode> var_list=new ArrayList<>();
		List<Parameter> new_params=new ArrayList<>();
		boolean is_reg=true;
		Address stack_base=null;
		int stack_size=0;
		for(int i=0; i<params.size(); i++) {
			if(i<idx || idx+count<=i) {
				new_params.add(params.get(i));
				continue;
			}

			for(Varnode var : params.get(i).getVariableStorage().getVarnodes()) {
				if(!var.isRegister()) {
					is_reg=false;
				} else if(!is_reg && var.isRegister()) {
					return false;
				}

				if(is_reg) {
					var_list.add(0, var);
				} else if(stack_base==null) {
					stack_base=var.getAddress();
					stack_size=var.getSize();
				} else {
					stack_size+=var.getSize();
				}
			}
		}
		if(stack_base!=null) {
			var_list.add(0, new Varnode(stack_base, stack_size));
		}

		try {
			VariableStorage storage = new VariableStorage(func.getProgram(), var_list.toArray(new Varnode[var_list.size()]));
			new_params.add(idx, new ParameterImpl(name, datatype, storage, func.getProgram(), SourceType.USER_DEFINED));
			params=new_params;
		}catch(Exception e) {
			Logger.append_message(String.format("Failed to insert function parameters: %s", e.getMessage()));
			return false;
		}
		return true;
	}

	private boolean init_func() {
		boolean is_go118=false;
		if(go_bin.ge_go_version(GolangVersion.GO_1_18_LOWEST)) {
			is_go118=true;
		}
		long entry_addr_value;
		try {
			entry_addr_value=go_bin.get_address_value(info_addr, is_go118?4:go_bin.get_pointer_size());
			if(is_go118) {
				Address pcheader_base=go_bin.get_pcheader_base();
				entry_addr_value+=go_bin.get_address_value(pcheader_base, 8+go_bin.get_pointer_size()*2, go_bin.get_pointer_size());
			}
			func_addr=go_bin.get_address(entry_addr_value);
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to get func addr: info_addr=%s, message=%s", info_addr, e.getMessage()));
			return false;
		}
		if(disasm_option) {
			disassemble();
		}
		func=go_bin.get_function(func_addr).orElse(null);
		if(func==null) {
			go_bin.create_function(func_name, func_addr);
			func=go_bin.get_function(func_addr).orElse(null);
		}
		if(func==null) {
			Logger.append_message(String.format("Failed to get function: %x", entry_addr_value));
			return false;
		}

		if(!init_func_name()) {
			return false;
		}
		if(!init_file_line_map()) {
			return false;
		}
		if(!init_params()) {
			return false;
		}

		for(GolangDatatypeRecord record : service.get_datatype_map().values()) {
			// Disable in the next release
			/*if(func_name.equals("fmt.Fprintln")) {
				if(record.get_name().equals("io.Writer")) {
					insert_params("w", 0, record.get_struct());
				} else if(record.get_name().equals("[]interface {}")) {
					insert_params("a", go_bin.get_pointer_size()*2, record.get_struct());
				}
				continue;
			}
			if(func_name.equals("fmt.Println")) {
				if(record.get_name().equals("[]interface {}")) {
					insert_params("a", 0, record.get_struct());
					break;
				}
				continue;
			}*/

			if(record.get_uncommon_type().isEmpty()) {
				continue;
			}
			for(UncommonMethod method : record.get_uncommon_type().get().get_method_list()) {
				long addr_value;
				if(method.get_normal_method_addr().isPresent()) {
					addr_value=method.get_normal_method_addr().get();
				} else if(method.get_interface_method_addr().isPresent()) {
					addr_value=method.get_interface_method_addr().get();
				} else {
					continue;
				}
				if(addr_value==func_addr.getOffset()) {
					insert_params("this", 0, record.get_datatype());
				}
			}
		}

		return true;
	}

	private boolean init_func_name() {
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
		Address func_name_addr;
		try {
			int func_name_offset=(int)go_bin.get_address_value(info_addr, is_go118?4:pointer_size, 4);
			if(is_go118) {
				Address func_name_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*3, pointer_size));
				func_name_addr=go_bin.get_address(func_name_base, func_name_offset);
			}else if(is_go116) {
				Address func_name_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*2, pointer_size));
				func_name_addr=go_bin.get_address(func_name_base, func_name_offset);
			}else {
				func_name_addr=go_bin.get_address(pcheader_base, func_name_offset);
			}
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to get func name addr: info_addr=%s, message=%s", info_addr, e.getMessage()));
			return false;
		}

		String str=go_bin.create_string_data(func_name_addr).orElse(null);
		if(str==null) {
			return false;
		}
		func_name=str;
		return true;
	}

	private boolean init_file_line_map() {
		boolean is_go116=false;
		boolean is_go118=false;
		if(go_bin.ge_go_version(GolangVersion.GO_1_16_LOWEST)) {
			is_go116=true;
		}
		if(go_bin.ge_go_version(GolangVersion.GO_1_18_LOWEST)) {
			is_go118=true;
		}

		file_line_comment_map = new HashMap<>();

		int pointer_size=go_bin.get_pointer_size();
		Address pcheader_base=go_bin.get_pcheader_base();
		Address pcln_base;
		try {
			int pcln_offset=(int)go_bin.get_address_value(info_addr, (is_go118?4:pointer_size)+5*4, 4);
			if(is_go118) {
				pcln_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*6, pointer_size));
				pcln_base=go_bin.get_address(pcln_base, pcln_offset);
			}else if(is_go116) {
				pcln_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*5, pointer_size));
				pcln_base=go_bin.get_address(pcln_base, pcln_offset);
			}else {
				pcln_base=go_bin.get_address(pcheader_base, pcln_offset);
			}
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to get pcln base: info_addr=%s, message=%s", info_addr, e.getMessage()));
			return false;
		}

		long line_num=-1;
		int i=0;
		boolean first=true;
		int pc_offset=0;
		List<PcFile> pcfile_list=get_pc_to_file_name_list(pc_offset);
		while(true) {
			int line_num_add;
			int byte_size;
			try {
				line_num_add=read_pc_data(go_bin.get_address(pcln_base, i));
				i+=Integer.toBinaryString(line_num_add).length()/8+1;
				byte_size=read_pc_data(go_bin.get_address(pcln_base, i));
				i+=Integer.toBinaryString(byte_size).length()/8+1;
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to get line num: info_addr=%s, message=%s", info_addr, e.getMessage()));
				return false;
			}
			if(line_num_add==0 && !first) {
				break;
			}

			first=false;
			int key=pc_offset;
			line_num_add=zig_zag_decode(line_num_add);
			line_num+=line_num_add;
			pc_offset+=byte_size*go_bin.get_quantum();
			String file_name="not_found";
			for(PcFile pcfile : pcfile_list) {
				if(pcfile.offset<pc_offset && pc_offset<=pcfile.offset+pcfile.size && pcfile.name!=null) {
					file_name=pcfile.name;
					break;
				}
			}

			file_line_comment_map.put(key, new FileLine(func_addr, key, pc_offset-key, file_name, line_num));
		}
		return true;
	}

	private boolean init_frame_map() {
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
		Address pcsp_base;
		try {
			int pcsp_offset=(int)go_bin.get_address_value(info_addr, (is_go118?4:pointer_size)+3*4, 4);
			if(is_go118) {
				pcsp_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*6, pointer_size));
				pcsp_base=go_bin.get_address(pcsp_base, pcsp_offset);
			}else if(is_go116) {
				pcsp_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*5, pointer_size));
				pcsp_base=go_bin.get_address(pcsp_base, pcsp_offset);
			}else {
				pcsp_base=go_bin.get_address(pcheader_base, pcsp_offset);
			}
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to get pcsp base: info_addr=%s, message=%s", info_addr, e.getMessage()));
			return false;
		}

		long frame_size=-1;
		int i=0;
		boolean first=true;
		int pc_offset=0;
		while(true) {
			int frame_size_add;
			int byte_size;
			try {
				frame_size_add=read_pc_data(go_bin.get_address(pcsp_base, i));
				i+=Integer.toBinaryString(frame_size_add).length()/8+1;
				byte_size=read_pc_data(go_bin.get_address(pcsp_base, i));
				i+=Integer.toBinaryString(byte_size).length()/8+1;
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to get line num: info_addr=%s, message=%s", info_addr, e.getMessage()));
				return false;
			}
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

	/*private long get_frame(int pc_offset) {
		long frame_size=0;
		for(int i : frame_map.keySet()) {
			frame_size=frame_map.get(i);
			if(pc_offset<i) {
				break;
			}
		}
		return frame_size;
	}*/

	private class PcFile {
		int offset;
		int size;
		String name;

		public PcFile(int key, int size, String name) {
			this.offset=key;
			this.size=size;
			this.name=name;
		}
	}

	private List<PcFile> get_pc_to_file_name_list(int target_pc_offset) {
		boolean is_go116=false;
		boolean is_go118=false;
		if(go_bin.ge_go_version(GolangVersion.GO_1_16_LOWEST)) {
			is_go116=true;
		}
		if(go_bin.ge_go_version(GolangVersion.GO_1_18_LOWEST)) {
			is_go118=true;
		}

		List<PcFile> pcfile_list=new ArrayList<>();
		int pointer_size=go_bin.get_pointer_size();
		Address pcheader_base=go_bin.get_pcheader_base();
		Address pcfile_base;
		try {
			int pcfile_offset=(int)go_bin.get_address_value(info_addr, (is_go118?4:pointer_size)+4*4, 4);
			if(is_go118) {
				pcfile_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*6, pointer_size));
				pcfile_base=go_bin.get_address(pcfile_base, pcfile_offset);
			}else if(is_go116) {
				pcfile_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*5, pointer_size));
				pcfile_base=go_bin.get_address(pcfile_base, pcfile_offset);
			}else {
				pcfile_base=go_bin.get_address(pcheader_base, pcfile_offset);
			}
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to get pcfile base: info_addr=%s, message=%s", info_addr, e.getMessage()));
			return pcfile_list;
		}

		long file_no=-1;
		int i=0;
		boolean first=true;
		int pc_offset=0;
		while(true) {
			int file_no_add;
			int byte_size;
			try {
				file_no_add=read_pc_data(go_bin.get_address(pcfile_base, i));
				i+=Integer.toBinaryString(file_no_add).length()/8+1;
				byte_size=read_pc_data(go_bin.get_address(pcfile_base, i));
				i+=Integer.toBinaryString(byte_size).length()/8+1;
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to get line num: info_addr=%s, message=%s", info_addr, e.getMessage()));
				break;
			}

			if(file_no_add==0 && !first) {
				break;
			}
			first=false;
			int key=pc_offset;
			file_no_add=zig_zag_decode(file_no_add);
			file_no+=file_no_add;
			pc_offset+=byte_size*go_bin.get_quantum();

			if(!is_go116) {
				if((int)file_no-1<0 || file_name_list.size()<=(int)file_no-1) {
					Logger.append_message(String.format("File name list index out of range: func_addr=%s, index=%x", func_addr, (int)file_no-1));
					pcfile_list.add(new PcFile(key, pc_offset-key, null));
					continue;
				}
				pcfile_list.add(new PcFile(key, pc_offset-key, file_name_list.get((int)file_no-1)));
				continue;
			}

			Address file_name_addr;
			try {
				int cu_offset=(int)go_bin.get_address_value(info_addr, (is_go118?4:pointer_size)+4*7, 4);
				if(cu_offset==0xffffffff) {
					return pcfile_list;
				}
				Address cutab_base;
				if(is_go118) {
					cutab_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*4, pointer_size));
				}else {
					cutab_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*3, pointer_size));
				}

				long file_no_offset=go_bin.get_address_value(cutab_base, (cu_offset+file_no)*4, 4);
				Address file_base;
				if(is_go118) {
					file_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*5, pointer_size));
				}else {
					file_base=go_bin.get_address(pcheader_base, go_bin.get_address_value(pcheader_base, 8+pointer_size*4, pointer_size));
				}
				file_name_addr=go_bin.get_address(file_base, file_no_offset);
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to get file name addr: pcheader_addr=%s, pcfile_base=%s, file_no=%x, message=%s", pcheader_base, pcfile_base, file_no, e.getMessage()));
				break;
			}

			String file_name=go_bin.create_string_data(file_name_addr).orElse(String.format("not_found_%x", file_name_addr.getOffset()));
			service.add_filename(file_name);
			pcfile_list.add(new PcFile(key, pc_offset-key, file_name));
		}
		return pcfile_list;
	}

	private int zig_zag_decode(int value) {
		if((value&1)!=0) {
			value=(value>>1)+1;
			value*=-1;
		}else {
			value>>=1;
		}
		return value;
	}

	private int read_pc_data(Address addr) throws BinaryAccessException {
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
}
