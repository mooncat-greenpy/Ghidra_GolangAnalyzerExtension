package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;


// debug/gosym/pclntab.go
public class FunctionModifier{
	GolangBinary go_bin=null;

	long func_num=0;
	List<GolangFunction> gofunc_list=null;
	List<String> file_name_list=null;
	boolean rename_option=false;
	boolean param_option=false;
	boolean comment_option=false;
	boolean extended_option=false;

	boolean ok=false;

	public FunctionModifier(GolangBinary go_bin, boolean rename_option, boolean param_option, boolean comment_option, boolean extended_option) {
		this.go_bin=go_bin;

		this.rename_option=rename_option;
		this.param_option=param_option;
		this.comment_option=comment_option;
		this.extended_option=extended_option;

		if(!rename_option && !param_option && !comment_option) {
			return;
		}

		if(!init_file_name_list()) {
			return;
		}
		if(!init_functions()) {
			return;
		}

		if(extended_option) {
			init_hardcode_functions();
		}

		this.ok=true;
	}

	boolean is_ok() {
		return ok;
	}

	boolean init_file_name_list() {
		boolean is_go116=false;
		if(go_bin.compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address gopclntab_base=go_bin.get_gopclntab_base();
		func_num=go_bin.get_address_value(gopclntab_base, 8, pointer_size);
		file_name_list=new ArrayList<>();
		if(is_go116) {
			return true;
		}
		Address func_list_base=go_bin.get_address(gopclntab_base, 8+pointer_size);
		if(func_list_base==null) {
			return false;
		}

		long file_name_table_offset=go_bin.get_address_value(func_list_base, func_num*pointer_size*2+pointer_size, pointer_size);
		Address file_name_table=go_bin.get_address(gopclntab_base, file_name_table_offset);
		long file_name_table_size=go_bin.get_address_value(file_name_table, 4);
		if(file_name_table==null || file_name_table_size==0) {
			return false;
		}

		for(int i=1;i<file_name_table_size;i++) {
			long file_name_offset=go_bin.get_address_value(file_name_table, 4*i,4);
			if(file_name_offset==0) {
				return false;
			}
			Address file_name_addr=go_bin.get_address(gopclntab_base, file_name_offset);
			if(file_name_addr==null) {
				return false;
			}
			file_name_list.add(go_bin.create_string_data(file_name_addr));
		}
		return true;
	}

	boolean init_functions() {
		boolean is_go116=false;
		if(go_bin.compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address gopclntab_base=go_bin.get_gopclntab_base();
		gofunc_list=new ArrayList<>();
		Address func_list_base=null;
		if(is_go116) {
			func_list_base=go_bin.get_address(gopclntab_base, go_bin.get_address_value(gopclntab_base, 8+pointer_size*6, pointer_size));
		}else {
			func_list_base=go_bin.get_address(gopclntab_base, 8+pointer_size);
		}
		if(func_list_base==null) {
			return false;
		}
		for(int i=0; i<func_num; i++) {
			long func_addr_value=go_bin.get_address_value(func_list_base, i*pointer_size*2, pointer_size);
			long func_info_offset=go_bin.get_address_value(func_list_base, i*pointer_size*2+pointer_size, pointer_size);
			Address func_info_addr=null;
			if(is_go116) {
				func_info_addr=go_bin.get_address(func_list_base, func_info_offset);
			}else {
				func_info_addr=go_bin.get_address(gopclntab_base, func_info_offset);
			}
			long func_entry_value=go_bin.get_address_value(func_info_addr, pointer_size);
			long func_end_value=go_bin.get_address_value(func_list_base, i*pointer_size*2+pointer_size*2, pointer_size);

			if(func_addr_value==0 || func_info_offset==0 || func_entry_value==0) {
				return false;
			}
			if(func_addr_value!=func_entry_value)
			{
				Logger.append_message(String.format("Function addr mismatch: %x != %x", func_addr_value, func_entry_value));
				continue;
			}

			GolangFunction gofunc=null;
			if(go_bin.is_x86()) {
				gofunc=new GolangFunctionX86(go_bin, func_info_addr, func_end_value-func_entry_value, file_name_list, extended_option);
			}else if(go_bin.is_arm()) {
				gofunc=new GolangFunctionArm(go_bin, func_info_addr, func_end_value-func_entry_value, file_name_list, extended_option);
			}else {
				gofunc=new GolangFunction(go_bin, func_info_addr, func_end_value-func_entry_value, file_name_list, extended_option);
			}
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
		Instruction inst=go_bin.get_instruction(func.getEntryPoint());
		MEMCPY_FUNC_STAGE stage=MEMCPY_FUNC_STAGE.GET_SRC;
		Register dst_reg=null;
		Register src_reg=null;
		DataType inner_datatype=null;
		String tmp_reg1="TMP";
		String tmp_reg2="TMP";
		int size=0;
		while(inst!=null) {
			if(go_bin.is_ret_inst(inst)) {
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
				if(mnemonic.contains("MOV")) {
					tmp_reg1=op1[0].toString();
					if(!(op2[0] instanceof Register) || !go_bin.compare_register((Register)op2[0], go_bin.get_register("SI"))) {
						return false;
					}
					src_reg=(Register)op2[0];
					stage=MEMCPY_FUNC_STAGE.ADD_SRC;
				}else if(mnemonic.equals("ldr")) {
					if(op2.length<2) {
						return false;
					}
					if(!(op1[0] instanceof Register)) {
						return false;
					}
					if(!(op2[0] instanceof Register)) {
						return false;
					}
					if(!(op2[1] instanceof Scalar)) {
						return false;
					}
					src_reg=(Register)op2[0];
					tmp_reg1=op1[0].toString();
					stage=MEMCPY_FUNC_STAGE.SET_DST;
				}else if(mnemonic.equals("ldp")) {
					if(inst.getNumOperands()<3) {
						return false;
					}
					Object op3[]=inst.getOpObjects(2);
					if(op3.length<1) {
						return false;
					}
					if(!(op1[0] instanceof Register)) {
						return false;
					}
					if(!(op2[0] instanceof Register)) {
						return false;
					}
					if(!(op3[0] instanceof Register)) {
						return false;
					}
					src_reg=(Register)op3[0];
					tmp_reg1=op1[0].toString();
					tmp_reg2=op2[0].toString();
					stage=MEMCPY_FUNC_STAGE.SET_DST;
				}
				break;
			case ADD_SRC:
				if(!mnemonic.equals("ADD")) {
					return false;
				}
				if(!(op1[0] instanceof Register) || !go_bin.compare_register((Register)op1[0], go_bin.get_register("SI"))) {
					return false;
				}
				if(!(op2[0] instanceof Scalar)) {
					return false;
				}
				size+=Integer.decode(op2[0].toString());
				stage=MEMCPY_FUNC_STAGE.SET_DST;
				break;
			case SET_DST:
				if(mnemonic.contains("MOV")) {
					if(!(op1[0] instanceof Register) || !go_bin.compare_register((Register)op1[0], go_bin.get_register("DI"))) {
						return false;
					}
					if(!op2[0].toString().equals(tmp_reg1)) {
						return false;
					}
					if(dst_reg==null) {
						dst_reg=(Register)op1[0];
						if(op2[0].toString().contains("XMM")) {
							inner_datatype=go_bin.get_unsigned_number_datatype(4);
						}else {
							inner_datatype=go_bin.get_unsigned_number_datatype(((Register)op2[0]).getBitLength()/8);
						}
					}
					stage=MEMCPY_FUNC_STAGE.ADD_DST;
				}else if(mnemonic.equals("str")) {
					if(op2.length<2) {
						return false;
					}
					if(!(op1[0] instanceof Register) || !go_bin.compare_register((Register)op1[0], go_bin.get_register(tmp_reg1))) {
						return false;
					}
					if(!(op2[0] instanceof Register)) {
						return false;
					}
					if(!(op2[1] instanceof Scalar)) {
						return false;
					}
					if(dst_reg==null) {
						dst_reg=(Register)op2[0];
						inner_datatype=go_bin.get_unsigned_number_datatype(((Register)op1[0]).getBitLength()/8);
					}
					size+=Integer.decode(op2[1].toString());
					stage=MEMCPY_FUNC_STAGE.GET_SRC;
				}else if(mnemonic.equals("stp")) {
					if(inst.getNumOperands()<3) {
						return false;
					}
					Object op3[]=inst.getOpObjects(2);
					if(op3.length<1) {
						return false;
					}
					if(!(op1[0] instanceof Register) || !go_bin.compare_register((Register)op1[0], go_bin.get_register(tmp_reg1))) {
						return false;
					}
					if(!(op2[0] instanceof Register) || !go_bin.compare_register((Register)op2[0], go_bin.get_register(tmp_reg2))) {
						return false;
					}
					if(!(op3[0] instanceof Register)) {
						return false;
					}
					if(dst_reg==null) {
						dst_reg=(Register)op3[0];
						inner_datatype=go_bin.get_unsigned_number_datatype(((Register)op1[0]).getBitLength()/8);
					}
					if(op3.length>=2 && op3[1] instanceof Scalar) {
						size+=Integer.decode(op3[1].toString());
					}else {
						size+=0x10;
					}
					stage=MEMCPY_FUNC_STAGE.GET_SRC;
				}
				break;
			case ADD_DST:
				if(!mnemonic.equals("ADD")) {
					return false;
				}
				if(!(op1[0] instanceof Register) || !go_bin.compare_register((Register)op1[0], go_bin.get_register("DI"))) {
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
		try {
			if(dst_reg==null || inner_datatype==null) {
				return false;
			}

			int pointer_size=go_bin.get_pointer_size();
			params.add(new ParameterImpl(String.format("param_%d", 1), new PointerDataType(inner_datatype, pointer_size), dst_reg, func.getProgram(), SourceType.USER_DEFINED));

			if(src_reg!=null) {
				params.add(new ParameterImpl(String.format("param_%d", 2), new PointerDataType(inner_datatype, pointer_size), src_reg, func.getProgram(), SourceType.USER_DEFINED));
			}
		} catch (InvalidInputException e) {
		}
		GolangFunction gofunc=new GolangFunction(go_bin, func, String.format("runtime.duffcopy_%#x_%s", size, func.getName()), params, extended_option);
		gofunc_list.add(gofunc);

		return true;
	}

	boolean check_memset(Function func) {
		Instruction inst=go_bin.get_instruction(func.getEntryPoint());
		Register dst_reg=null;
		Register src_reg=null;
		DataType inner_datatype=null;
		int start=-1;
		int size=0;
		while(inst!=null) {
			if(go_bin.is_ret_inst(inst)) {
				break;
			}

			String mnemonic=inst.getMnemonicString();
			if(inst.getNumOperands()<1) {
				return false;
			}
			Object op1[]=inst.getOpObjects(0);
			if(op1.length>=2 && mnemonic.equals("STOSD")) {
				if(!(op1[1] instanceof Register) || !go_bin.compare_register((Register)op1[1], go_bin.get_register("DI"))) {
					return false;
				}
				if(start<0) {
					start=0;
					dst_reg=(Register)op1[1];
					src_reg=go_bin.get_register("EAX");
					inner_datatype=go_bin.get_unsigned_number_datatype(src_reg.getBitLength()/8);
				}
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
				if(!(op1[0] instanceof Register) || !go_bin.compare_register((Register)op1[0], go_bin.get_register("DI"))) {
					return false;
				}
				if(!(op2[0] instanceof Register) || !op2[0].toString().contains("XMM")) {
					return false;
				}
				if(start<0) {
					dst_reg=(Register)op1[0];
					src_reg=(Register)op2[0];
					inner_datatype=go_bin.get_unsigned_number_datatype(4);
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
			}else if(mnemonic.equals("LEA")) {
				if(op2.length<2) {
					return false;
				}
				if(!go_bin.compare_register((Register)op1[0], go_bin.get_register("DI"))) {
					return false;
				}
				if(!go_bin.compare_register((Register)op2[0], go_bin.get_register("DI"))) {
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
				if(!(op1[0] instanceof Register)) {
					return false;
				}
				if(!(op2[0] instanceof Register)) {
					return false;
				}
				if(!(op2[1] instanceof Scalar)) {
					return false;
				}
				if(start<0) {
					start=0;
					dst_reg=(Register)op2[0];
					src_reg=(Register)op1[0];
					inner_datatype=go_bin.get_unsigned_number_datatype(src_reg.getBitLength()/8);
				}
				size+=Integer.decode(op2[1].toString());
			}else if(mnemonic.equals("stp")) {
				if(inst.getNumOperands()<3) {
					return false;
				}
				Object op3[]=inst.getOpObjects(2);
				if(op3.length<1) {
					return false;
				}
				if(!(op1[0] instanceof Register) || !go_bin.compare_register((Register)op1[0], go_bin.get_register("xzr"))) {
					return false;
				}
				if(!(op2[0] instanceof Register) || !go_bin.compare_register((Register)op2[0], go_bin.get_register("xzr"))) {
					return false;
				}
				if(!(op3[0] instanceof Register)) {
					return false;
				}
				if(start<0) {
					start=0;
					dst_reg=(Register)op3[0];
					inner_datatype=go_bin.get_unsigned_number_datatype(((Register)op1[0]).getBitLength()/8);
				}
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
			if(dst_reg==null || inner_datatype==null) {
				return false;
			}

			params.add(new ParameterImpl(String.format("param_%d", 1), new PointerDataType(inner_datatype, go_bin.get_pointer_size()), dst_reg, func.getProgram(), SourceType.USER_DEFINED));

			if(src_reg!=null) {
				params.add(new ParameterImpl(String.format("param_%d", 2), go_bin.get_unsigned_number_datatype(src_reg.getBitLength()/8), src_reg, func.getProgram(), SourceType.USER_DEFINED));
			}
		} catch (InvalidInputException e) {
		}
		GolangFunction gofunc=new GolangFunction(go_bin, func, String.format("runtime.duffzero_%#x_%#x_%s", start, size, func.getName()), params, extended_option);
		gofunc_list.add(gofunc);

		return true;
	}

	boolean init_hardcode_functions(){
		for(Function func : go_bin.get_functions()) {
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
			Logger.append_message("Failed to setup FunctionModifier");
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
			Logger.append_message(String.format("Failed to set function name: %s", e.getMessage()));
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
			func.setReturnType(new VoidDataType(), SourceType.USER_DEFINED);
		}catch(Exception e) {
			Logger.append_message(String.format("Failed to set function parameters: %s", e.getMessage()));
		}
	}

	void add_func_comment(GolangFunction gofunc) {
		Address addr=gofunc.get_func_addr();
		Map<Integer, String> comment_map=gofunc.get_file_line_comment_map();

		for(Integer key: comment_map.keySet()) {
			go_bin.set_comment(go_bin.get_address(addr, key), ghidra.program.model.listing.CodeUnit.PRE_COMMENT, comment_map.get(key));
		}
	}
}
