package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.exception.InvalidInputException;


public class GolangFunctionArm extends GolangFunction {

	public GolangFunctionArm(GolangBinary go_bin, Address func_info_addr, long func_size, List<String> file_name_list, boolean extended_option) {
		super(go_bin, func_info_addr, func_size, file_name_list, extended_option);
	}

	public GolangFunctionArm(GolangBinary go_bin, Function func, boolean extended_option) {
		super(go_bin, func, extended_option);
	}

	private static final String[] reg_arg_str={};

	@Override
	boolean check_inst_builtin_reg_arg(Instruction inst, Map<Register, REG_FLAG> builtin_reg_state, List<Register> reg_arg) {
		if(inst.getMnemonicString().equals("ret") || inst.getMnemonicString().equals("b")) {
			return true;
		}
		Object op_input[]=inst.getInputObjects();
		Object op_output[]=inst.getResultObjects();

		for(int j=0;j<op_input.length;j++) {
			if(!(op_input[j] instanceof Register)) {
				continue;
			}
			Register reg=(Register)op_input[j];
			if(!builtin_reg_state.containsKey(reg.getBaseRegister()) &&
					inst.toString().contains(reg.toString()) &&
					(reg.getTypeFlags()&(Register.TYPE_PC|Register.TYPE_SP))==0 &&
					!reg.toString().contains("sp") &&
					!go_bin.compare_register(reg, go_bin.get_register("lr"))) {
				builtin_reg_state.put(reg.getBaseRegister(), REG_FLAG.READ);
				reg_arg.add(reg);
			}
		}
		for(int j=0;j<op_output.length;j++) {
			if(!(op_output[j] instanceof Register)) {
				continue;
			}
			Register reg=(Register)op_output[j];
			if(!builtin_reg_state.containsKey(reg.getBaseRegister())) {
				builtin_reg_state.put(reg.getBaseRegister(), REG_FLAG.WRITE);
			}
		}
		return false;
	}

	@Override
	String get_reg_arg_name(int arg_count) {
		if(arg_count<0 || reg_arg_str.length<=arg_count) {
			return "";
		}
		return reg_arg_str[arg_count];
	}

	enum MEMCPY_FUNC_STAGE {
		GET_SRC,
		SET_DST,
	}
	@Override
	boolean check_memcopy() {
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
				if(mnemonic.equals("ldr")) {
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
				}else {
					return false;
				}
				break;
			case SET_DST:
				if(mnemonic.equals("str")) {
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
				}else {
					return false;
				}
				break;
			}
			inst=inst.getNext();
		}
		if(size<=0) {
			return false;
		}

		params=new ArrayList<>();
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

		func_name=String.format("runtime.duffcopy_%#x_%s", size, func.getName());

		return true;
	}

	@Override
	boolean check_memset() {
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
			Object op2[]=inst.getOpObjects(1);
			if(inst.getNumOperands()<2) {
				return false;
			}
			if(op1.length<1 || op2.length<1) {
				return false;
			}
			if(mnemonic.equals("str")) {
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

		params=new ArrayList<>();
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

		func_name=String.format("runtime.duffzero_%#x_%#x_%s", start, size, func.getName());

		return true;
	}
}
