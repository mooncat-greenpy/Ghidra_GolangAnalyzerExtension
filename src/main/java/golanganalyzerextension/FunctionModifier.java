package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;


// debug/gosym/pclntab.go
public class FunctionModifier extends GolangBinary {
	long func_num=0;
	List<GolangFunction> gofunc_list=null;
	List<String> file_name_list=null;
	boolean rename_option=false;
	boolean param_option=false;
	boolean comment_option=false;

	public FunctionModifier(Program program, TaskMonitor monitor, MessageLog log, boolean rename_option, boolean param_option, boolean comment_option, boolean debugmode) {
		super(program, monitor, log, debugmode);

		this.rename_option=rename_option;
		this.param_option=param_option;
		this.comment_option=comment_option;

		if(!rename_option && !param_option && !comment_option) {
			return;
		}

		if(!init_gopclntab()) {
			return;
		}
		if(!init_file_name_list()) {
			return;
		}
		if(!init_functions()) {
			return;
		}

		init_hardcode_functions();

		ok=true;
	}

	boolean init_file_name_list() {
		boolean is_go116=false;
		if(compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		func_num=get_address_value(get_address(gopclntab_base, 8), pointer_size);
		file_name_list=new ArrayList<>();
		if(is_go116) {
			return true;
		}
		Address func_list_base=get_address(gopclntab_base, 8+pointer_size);
		if(func_list_base==null) {
			return false;
		}

		long file_name_table_offset=get_address_value(get_address(func_list_base, func_num*pointer_size*2+pointer_size), pointer_size);
		Address file_name_table=get_address(gopclntab_base, file_name_table_offset);
		long file_name_table_size=get_address_value(file_name_table, 4);
		if(file_name_table==null || file_name_table_size==0) {
			return false;
		}

		for(int i=1;i<file_name_table_size;i++) {
			long file_name_offset=get_address_value(get_address(file_name_table, 4*i),4);
			if(file_name_offset==0) {
				return false;
			}
			Address file_name_addr=get_address(gopclntab_base, file_name_offset);
			if(file_name_addr==null) {
				return false;
			}
			file_name_list.add(create_string_data(file_name_addr));
		}
		return true;
	}

	boolean init_functions() {
		boolean is_go116=false;
		if(compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		gofunc_list=new ArrayList<>();
		Address func_list_base=null;
		if(is_go116) {
			func_list_base=get_address(gopclntab_base, get_address_value(get_address(gopclntab_base, 8+pointer_size*6), pointer_size));
		}else {
			func_list_base=get_address(gopclntab_base, 8+pointer_size);
		}
		if(func_list_base==null) {
			return false;
		}
		for(int i=0; i<func_num; i++) {
			long func_addr_value=get_address_value(get_address(func_list_base, i*pointer_size*2), pointer_size);
			long func_info_offset=get_address_value(get_address(func_list_base, i*pointer_size*2+pointer_size), pointer_size);
			Address func_info_addr=null;
			if(is_go116) {
				func_info_addr=get_address(func_list_base, func_info_offset);
			}else {
				func_info_addr=get_address(gopclntab_base, func_info_offset);
			}
			long func_entry_value=get_address_value(func_info_addr, pointer_size);
			long func_end_value=get_address_value(get_address(func_list_base, i*pointer_size*2+pointer_size*2), pointer_size);

			if(func_addr_value==0 || func_info_offset==0 || func_entry_value==0) {
				return false;
			}
			if(func_addr_value!=func_entry_value)
			{
				append_message(String.format("Function addr mismatch: %x != %x", func_addr_value, func_entry_value));
				continue;
			}

			GolangFunction gofunc=new GolangFunction(this, func_info_addr, func_end_value-func_entry_value);
			gofunc_list.add(gofunc);
		}
		return true;
	}

	enum MEMCPY_FUNC_STAGE {
		GET_SRC,
		ADD_SRC,
		SET_DST,
		ADD_DST,
	}
	boolean check_memcopy(Function func) {
		Instruction inst=program_listing.getInstructionAt(func.getEntryPoint());
		MEMCPY_FUNC_STAGE stage=MEMCPY_FUNC_STAGE.GET_SRC;
		String tmp_reg="TMP";
		int size=0;
		while(inst!=null) {
			if(inst.toString().contains("RET")) {
				break;
			}

			String mnemonic=inst.getMnemonicString();
			if(inst.getNumOperands()<2) {
				return false;
			}
			Object op1[]=inst.getOpObjects(0);
			Object op2[]=inst.getOpObjects(1);
			if(op1.length<1 || op2.length<1) {
				return false;
			}
			switch(stage) {
			case GET_SRC:
				if(!mnemonic.contains("MOV")) {
					return false;
				}
				tmp_reg=op1[0].toString();
				if(!op2[0].toString().equals(pointer_size==8?"RSI":"ESI")) {
					return false;
				}
				stage=MEMCPY_FUNC_STAGE.ADD_SRC;
				break;
			case ADD_SRC:
				if(!mnemonic.equals("ADD")) {
					return false;
				}
				if(!op1[0].toString().equals(pointer_size==8?"RSI":"ESI")) {
					return false;
				}
				if(!(op2[0] instanceof Scalar)) {
					return false;
				}
				size+=Integer.decode(op2[0].toString());
				stage=MEMCPY_FUNC_STAGE.SET_DST;
				break;
			case SET_DST:
				if(!mnemonic.contains("MOV")) {
					return false;
				}
				if(!op1[0].toString().equals(pointer_size==8?"RDI":"EDI")) {
					return false;
				}
				if(!op2[0].toString().equals(tmp_reg)) {
					return false;
				}
				stage=MEMCPY_FUNC_STAGE.ADD_DST;
				break;
			case ADD_DST:
				if(!mnemonic.equals("ADD")) {
					return false;
				}
				if(!op1[0].toString().equals(pointer_size==8?"RDI":"EDI")) {
					return false;
				}
				if(!(op2[0] instanceof Scalar)) {
					return false;
				}
				stage=MEMCPY_FUNC_STAGE.GET_SRC;
				break;
			}
			inst=inst.getNext();
		}
		if(size<=0) {
			return false;
		}

		List<Parameter> params=new ArrayList<>();
		String reg_names[]= {pointer_size==8?"RDI":"EDI", pointer_size==8?"RSI":"ESI"};
		for(int i=0;i<reg_names.length;i++) {
			try {
				DataType data_type=new ByteDataType();
				ArrayDataType array_datatype=new ArrayDataType(data_type, size, data_type.getLength());
				params.add(new ParameterImpl(String.format("param_%d", i+1), new PointerDataType(array_datatype, pointer_size), program.getRegister(reg_names[i]), func.getProgram(), SourceType.USER_DEFINED));
			} catch (InvalidInputException e) {
			}
		}
		GolangFunction gofunc=new GolangFunction(this, func, String.format("runtime.duffcopy_%#x_%s", size, func.getName()), params);
		gofunc_list.add(gofunc);

		return true;
	}

	boolean check_memset(Function func) {
		Instruction inst=program_listing.getInstructionAt(func.getEntryPoint());
		Register dst_reg=null;
		Register src_reg=null;
		int start=-1;
		int size=0;
		while(inst!=null) {
			if(inst.toString().toUpperCase().contains("RET") || inst.toString().equals("add pc,lr,#0x0")) {
				break;
			}

			String mnemonic=inst.getMnemonicString();
			if(inst.getNumOperands()<1) {
				return false;
			}
			Object op1[]=inst.getOpObjects(0);
			if(op1.length>=2 && mnemonic.equals("STOSD")) {
				if(!(op1[1] instanceof Register) || !compare_register((Register)op1[1], program.getRegister("DI"))) {
					return false;
				}
				start=0;
				dst_reg=(Register)op1[1];
				src_reg=program.getRegister("EAX");
				size+=4;
				inst=inst.getNext();
				continue;
			}
			Object op2[]=inst.getOpObjects(1);
			if(inst.getNumOperands()<2) {
				return false;
			}
			if(op1.length<1 || op2.length<1) {
				return false;
			}
			if(mnemonic.equals("MOVUPS")) {
				if(!(op1[0] instanceof Register) || !compare_register((Register)op1[0], program.getRegister("DI"))) {
					return false;
				}
				if(op1.length<2) {
					if(start<0) {
						start=0;
					}
				}else {
					if(!(op1[1] instanceof Scalar)) {
						return false;
					}
					if(start<0) {
						start=Integer.decode(op1[1].toString());
					}
				}
				if(!(op2[0] instanceof Register) || !op2[0].toString().contains("XMM")) {
					return false;
				}
				dst_reg=(Register)op1[0];
				src_reg=(Register)op2[0];
			}else if(mnemonic.equals("LEA")) {
				if(op2.length<2) {
					return false;
				}
				if(!compare_register((Register)op1[0], program.getRegister("DI"))) {
					return false;
				}
				if(!compare_register((Register)op2[0], program.getRegister("DI"))) {
					return false;
				}
				if(!(op2[1] instanceof Scalar)) {
					return false;
				}
				size+=Integer.decode(op2[1].toString());
			}else if(mnemonic.equals("str")) {
				if(op2.length<2) {
					return false;
				}
				if(!(op1[0] instanceof Register) || !compare_register((Register)op1[0], program.getRegister("r0"))) {
					return false;
				}
				if(!(op2[0] instanceof Register) || !compare_register((Register)op2[0], program.getRegister("r1"))) {
					return false;
				}
				if(!(op2[1] instanceof Scalar)) {
					return false;
				}
				if(start<0) {
					start=0;
				}
				dst_reg=(Register)op2[0];
				src_reg=(Register)op1[0];
				size+=Integer.decode(op2[1].toString());
			}else if(mnemonic.equals("stp")) {
				if(inst.getNumOperands()<3) {
					return false;
				}
				Object op3[]=inst.getOpObjects(2);
				if(op3.length<1) {
					return false;
				}
				if(!compare_register((Register)op1[0], program.getRegister("xzr"))) {
					return false;
				}
				if(!compare_register((Register)op2[0], program.getRegister("xzr"))) {
					return false;
				}
				if(!(op3[0] instanceof Register) || !compare_register((Register)op3[0], program.getRegister("x20"))) {
					return false;
				}
				if(start<0) {
					start=0;
				}
				dst_reg=(Register)op3[0];
				if(op3.length>=2 && op3[1] instanceof Scalar) {
					size+=Integer.decode(op3[1].toString());
				}else {
					size+=0x10;
				}
			}else {
				return false;
			}
			inst=inst.getNext();
		}

		if(size<=0) {
			return false;
		}

		List<Parameter> params=new ArrayList<>();
		try {
			if(dst_reg==null) {
				return false;
			}

			DataType data_type=new ByteDataType();
			ArrayDataType array_datatype=new ArrayDataType(data_type, size, data_type.getLength());
			params.add(new ParameterImpl(String.format("param_%d", 1), new PointerDataType(array_datatype, pointer_size), dst_reg, func.getProgram(), SourceType.USER_DEFINED));

			if(src_reg!=null) {
				array_datatype=new ArrayDataType(data_type, src_reg.getBitLength()/8, data_type.getLength());
				params.add(new ParameterImpl(String.format("param_%d", 2), new PointerDataType(array_datatype, pointer_size), src_reg, func.getProgram(), SourceType.USER_DEFINED));
			}
		} catch (InvalidInputException e) {
		}
		GolangFunction gofunc=new GolangFunction(this, func, String.format("runtime.duffzero_%#x_%#x_%s", start, size, func.getName()), params);
		gofunc_list.add(gofunc);

		return true;
	}

	boolean init_hardcode_functions(){
		for(Function func : program.getFunctionManager().getFunctions(true)) {
			Address entry_addr=func.getEntryPoint();
			GolangFunction find=gofunc_list.stream().filter(v -> v.func_addr.equals(entry_addr)).findFirst().orElse(null);
			if(find!=null) {
				continue;
			}
			if(check_memcopy(func)) {
				continue;
			}
			if(check_memset(func)) {
				continue;
			}
		}
		return true;
	}

	void modify() {
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
			func.setName(func_name, SourceType.USER_DEFINED);
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
