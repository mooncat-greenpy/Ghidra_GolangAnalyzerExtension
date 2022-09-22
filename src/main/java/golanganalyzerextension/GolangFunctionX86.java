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


public class GolangFunctionX86 extends GolangFunction {

	public GolangFunctionX86(GolangBinary go_bin, GolangAnalyzerExtensionService service, Address func_info_addr, long func_size, boolean disasm_option, boolean extended_option) {
		super(go_bin, service, func_info_addr, func_size, disasm_option, extended_option);
	}

	public GolangFunctionX86(GolangBinary go_bin, GolangAnalyzerExtensionService service, Function func, boolean disasm_option, boolean extended_option) {
		super(go_bin, service, func, disasm_option, extended_option);
	}

	private static final String[] reg_arg_str={"RAX", "RBX", "RCX", "RDI", "RSI", "R8", "R9", "R10", "R11"};

	@Override
	boolean check_inst_builtin_reg_arg(Instruction inst, Map<Register, REG_FLAG> builtin_reg_state, List<Register> reg_arg) {
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
			if(inst.getMnemonicString().equals("XOR") &&
					(inst.getNumOperands()==2 && inst.getOpObjects(0).length>0 && inst.getOpObjects(1).length>0 &&
					inst.getOpObjects(0)[0].toString().equals(inst.getOpObjects(1)[0].toString()))) {
				continue;
			}
			if(inst.getMnemonicString().equals("PUSH") || inst.getMnemonicString().equals("XCHG")) {
				continue;
			}
			if(!builtin_reg_state.containsKey(reg.getBaseRegister()) &&
					inst.toString().contains(reg.toString()) &&
					(reg.getTypeFlags()&(Register.TYPE_PC|Register.TYPE_SP))==0 &&
					!reg.toString().contains("SP") &&
					// XMM15 is used as a zero register.
					!go_bin.compare_register(reg, go_bin.get_register("BP")) && !go_bin.compare_register(reg, go_bin.get_register("XMM15"))) {
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

	@Override
	boolean check_inst_reg_arg(Instruction inst, Map<Register, REG_FLAG> builtin_reg_state) {
		if(go_bin.compare_go_version("go1.17beta1")>0) {
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

		boolean is_target=false;
		for(int i=0;i<reg_arg_str.length;i++) {
			if(!reg_arg_str[i].equals(op2[0].toString())) {
				continue;
			}
			is_target=true;
			break;
		}
		if(is_target) {
			Register reg=(Register)op2[0];
			if(builtin_reg_state.containsKey(reg.getBaseRegister()) && builtin_reg_state.get(reg.getBaseRegister())==REG_FLAG.WRITE) {
				return false;
			}
			return true;
		}
		return false;
	}

	enum MEMCPY_FUNC_STAGE {
		GET_SRC,
		ADD_SRC,
		SET_DST,
		ADD_DST,
	}
	@Override
	boolean check_memcopy() {
		Instruction inst=go_bin.get_instruction(func.getEntryPoint());
		MEMCPY_FUNC_STAGE stage=MEMCPY_FUNC_STAGE.GET_SRC;
		Register dst_reg=null;
		Register src_reg=null;
		DataType inner_datatype=null;
		String tmp_reg1="TMP";
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
				if(!mnemonic.contains("MOV")) {
					return false;
				}
				tmp_reg1=op1[0].toString();
				if(!(op2[0] instanceof Register) || !go_bin.compare_register((Register)op2[0], go_bin.get_register("SI"))) {
					return false;
				}
				src_reg=(Register)op2[0];
				stage=MEMCPY_FUNC_STAGE.ADD_SRC;
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
				if(!mnemonic.contains("MOV")) {
					return false;
				}
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
