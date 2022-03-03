package golanganalyzerextension;


import java.math.BigInteger;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.data.Integer3DataType;
import ghidra.program.model.data.Integer5DataType;
import ghidra.program.model.data.Integer6DataType;
import ghidra.program.model.data.Integer7DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.UnsignedInteger16DataType;
import ghidra.program.model.data.UnsignedInteger3DataType;
import ghidra.program.model.data.UnsignedInteger5DataType;
import ghidra.program.model.data.UnsignedInteger6DataType;
import ghidra.program.model.data.UnsignedInteger7DataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.lang.Register;
import ghidra.program.model.listing.ContextChangeException;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;


public class GolangBinary {
	private Program program=null;
	private TaskMonitor monitor=null;
	private Listing program_listing=null;
	private Memory memory=null;

	private boolean ok=false;

	private Address gopclntab_base=null;
	private int magic=0;
	private int quantum=0;
	private int pointer_size=0;

	private String go_version="";
	private String go_version_mod="";

	public GolangBinary(Program program, TaskMonitor monitor) {
		this.program=program;
		this.monitor=monitor;
		this.program_listing=program.getListing();
		this.memory=program.getMemory();

		if(!init_go_version()) {
			Logger.append_message("Failed to init go version");
		}
		if(!init_gopclntab()) {
			Logger.append_message("Failed to init gopclntab");
		}

		this.ok=true;
	}

	public GolangBinary(GolangBinary obj) {
		this.program=obj.program;
		this.monitor=obj.monitor;
		this.program_listing=obj.program_listing;
		this.memory=obj.memory;

		this.gopclntab_base=obj.gopclntab_base;
		this.magic=obj.magic;
		this.quantum=obj.quantum;
		this.pointer_size=obj.pointer_size;
		this.go_version=obj.go_version;
		this.go_version_mod=obj.go_version_mod;

		this.ok=true;
	}

	public boolean is_ok() {
		return ok;
	}

	public Address get_address(Address base, long offset) {
		if(base==null) {
			return null;
		}
		try {
			return base.add(offset);
		}catch(AddressOutOfBoundsException e) {
			Logger.append_message(String.format("Failed to get address: %s %x+%x", e.getMessage(), base.getOffset(), offset));
		}
		return null;
	}

	public Address get_address(long addr_value) {
		return program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_value);
	}

	public Address get_address(String addr_str) {
		return program.getAddressFactory().getAddress(addr_str);
	}

	public boolean is_valid_address(Address addr) {
		boolean ret=false;
		try {
			memory.getByte(addr);
			ret=true;
		} catch (MemoryAccessException e) {
			ret=false;
		}
		return ret;
	}

	public boolean is_valid_address(long addr_value) {
		return is_valid_address(get_address(addr_value));
	}

	public long get_address_value(Address addr, int size) {
		if(addr==null) {
			return 0;
		}
		try {
			if(size==8) {
				return memory.getLong(addr);
			}else if(size==4) {
				return memory.getInt(addr);
			}else if(size==2) {
				return memory.getShort(addr);
			}
			return memory.getByte(addr)&0xff;
		}catch(MemoryAccessException e) {
			Logger.append_message(String.format("Failed to get value: %s %x", e.getMessage(), addr.getOffset()));
		}
		return 0;
	}

	public long get_address_value(Address addr, long offset, int size) {
		if(addr==null) {
			return 0;
		}
		return get_address_value(get_address(addr, offset), size);
	}

	public Address find_memory(Address base_addr, byte[] target, byte[] mask) {
		return memory.findBytes(base_addr, target, mask, true, monitor);
	}

	public DataType get_unsigned_number_datatype(int size) {
		if(size==1) {
			return new ByteDataType();
		}else if(size==2) {
			return new UnsignedShortDataType();
		}else if(size==3) {
			return new UnsignedInteger3DataType();
		}else if(size==4) {
			return new UnsignedIntegerDataType();
		}else if(size==5) {
			return new UnsignedInteger5DataType();
		}else if(size==6) {
			return new UnsignedInteger6DataType();
		}else if(size==7) {
			return new UnsignedInteger7DataType();
		}else if(size==8) {
			return new UnsignedLongLongDataType();
		}else if(size==16) {
			return new UnsignedInteger16DataType();
		}else if(pointer_size==8) {
			return new UnsignedLongLongDataType();
		}else {
			return new UnsignedIntegerDataType();
		}
	}

	public DataType get_signed_number_datatype(int size) {
		if(size==1) {
			return new SignedByteDataType();
		}else if(size==2) {
			return new ShortDataType();
		}else if(size==3) {
			return new Integer3DataType();
		}else if(size==4) {
			return new IntegerDataType();
		}else if(size==5) {
			return new Integer5DataType();
		}else if(size==6) {
			return new Integer6DataType();
		}else if(size==7) {
			return new Integer7DataType();
		}else if(size==8) {
			return new LongLongDataType();
		}else if(size==16) {
			return new Integer16DataType();
		}else if(pointer_size==8) {
			return new LongLongDataType();
		}else {
			return new IntegerDataType();
		}
	}

	public void clear_data(Address addr, long size) {
		program_listing.clearCodeUnits(addr, addr.add(size), false);
	}

	public String read_string(Address addr, int size) {
		try {
			byte[] bytes=new byte[size];
			memory.getBytes(addr, bytes, 0, size);
			return new String(bytes);
		} catch (MemoryAccessException e) {
			Logger.append_message(String.format("Failed to read string: %s %x", e.getMessage(), addr.getOffset()));
		}
		return "not found";
	}

	public String read_string_struct(Address string_struct_addr, int value_size) {
		if(!is_valid_address(string_struct_addr)) {
			return null;
		}
		Address string_addr=program.getAddressFactory().getAddress(
				String.format("%x", get_address_value(string_struct_addr, value_size)));
		if(!is_valid_address(string_addr)) {
			return null;
		}
		long string_size=get_address_value(string_struct_addr, value_size, value_size);
		return read_string(string_addr, (int)string_size);
	}

	public String read_string_struct(long string_struct_addr_value, int value_size) {
		return read_string_struct(program.getAddressFactory().getAddress(String.format("%x", string_struct_addr_value)), value_size);
	}

	public String create_string_data(Address addr) {
		if(addr==null) {
			return "not found";
		}
		clear_data(addr, 1);
		Data string_data=program_listing.getDefinedDataAt(addr);
		if(string_data==null) {
			try {
				string_data=program_listing.createData(addr, new StringDataType());
				if(!string_data.getDataType().isEquivalent((new StringDataType()))) {
					return "not found";
				}
			} catch (CodeUnitInsertionException | DataTypeConflictException e) {
				Logger.append_message(String.format("Failed to create string data: %s %x", e.getMessage(), addr.getOffset()));
			}
		}
		if(string_data==null) {
			Address zero_addr=memory.findBytes(addr, new byte[] {(byte)0x0}, new byte[] {(byte)0xff}, true, monitor);
			if(zero_addr==null) {
				return "not found";
			}
			int size=(int)(zero_addr.getOffset()-addr.getOffset());
			return read_string(addr, size);
		}
		return (String)string_data.getValue();
	}

	public void create_data(Address addr, DataType datatype) throws CodeUnitInsertionException, DataTypeConflictException {
		clear_data(addr, datatype.getLength());
		program.getListing().createData(addr, datatype);
	}

	public Function get_function(Address addr) {
		return program.getFunctionManager().getFunctionAt(addr);
	}

	public FunctionIterator get_functions() {
		return program.getFunctionManager().getFunctions(true);
	}

	public void create_function(String name, Address addr) {
		CreateFunctionCmd cmd=new CreateFunctionCmd(name, addr, null, SourceType.ANALYSIS);
		cmd.applyTo(program, monitor);
	}

	public boolean is_x86() {
		return program.getLanguage().getProcessor().toString().equals("x86");
	}

	public boolean is_arm() {
		return program.getLanguage().getProcessor().toString().equals("ARM") || program.getLanguage().getProcessor().toString().equals("AARCH64");
	}

	public void disassemble(Address addr, long size) {
		clear_data(addr, size);
		Address target=addr;
		Disassembler disassembler=Disassembler.getDisassembler(program, monitor, new DisassemblerMessageListener() {
			@Override
			public void disassembleMessageReported(String msg) {
				Logger.append_message(msg);
			}
		});
		AddressSet addr_set=new AddressSet(program, addr, addr.add(size));
		while(target.getOffset()<addr.add(size).getOffset()) {
			disassembler.disassemble(target, addr_set, true);
			Instruction inst=get_instruction(target);
			if (inst==null) {
				return;
			}
			target=target.add(inst.getLength());
		}
	}

	public Instruction get_instruction(Address addr) {
		return program_listing.getInstructionAt(addr);
	}

	public boolean is_ret_inst(Instruction inst) {
		if(inst.toString().toUpperCase().contains("RET") || inst.toString().toLowerCase().equals("add pc,lr,#0x0")) {
			return true;
		}
		return false;
	}

	public Register get_register(String reg_str) {
		return program.getRegister(reg_str);
	}

	public BigInteger get_register_value(Register reg, Address addr) {
		return program.getProgramContext().getRegisterValue(reg, addr).getSignedValue();
	}

	public void set_register_value(Register reg, Address start, Address end, BigInteger value) throws ContextChangeException {
		program.getProgramContext().setValue(reg, start, end, value);
	}

	public boolean compare_register(Register cmp1, Register cmp2) {
		if(cmp1==null || cmp2==null) {
			return false;
		}
		return cmp1.getBaseRegister().equals(cmp2.getBaseRegister());
	}

	public void create_label(Address addr, String str) {
		try {
			str=str.replace(" ", "_");
			program.getSymbolTable().createLabel(addr, str, ghidra.program.model.symbol.SourceType.USER_DEFINED);
		} catch (InvalidInputException e) {
			Logger.append_message(String.format("Failed to create label: %x %s", addr.getOffset(), str));
		}
	}

	public void set_comment(Address addr, int type, String comment) {
		program.getListing().setComment(addr, type, comment);
	}

	public Address get_gopclntab_base() {
		return gopclntab_base;
	}

	public int get_pointer_size() {
		return pointer_size;
	}

	public int get_quantum() {
		return quantum;
	}

	private Address search_gopclntab() {
		MemoryBlock gopclntab_section=null;
		for (MemoryBlock mb : memory.getBlocks()) {
			if(mb.getName().equals(".gopclntab")) {
				gopclntab_section=mb;
			}
		}
		if(gopclntab_section!=null) {
			return gopclntab_section.getStart();
		}

		// debug/gosym/pclntab.go
		byte go12_magic[]= {(byte)0xfb,(byte)0xff,(byte)0xff,(byte)0xff};
		boolean is_go116=false;
		if(compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
			go12_magic[0]=(byte)0xfa;
		}

		Address tmp_gopclntab_base=null;
		while(true) {
			tmp_gopclntab_base=memory.findBytes(tmp_gopclntab_base, go12_magic, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff}, true, monitor);
			if(tmp_gopclntab_base==null) {
				break;
			}

			int tmp_quantum=(int)get_address_value(tmp_gopclntab_base, 6, 1);
			int tmp_pointer_size=(int)get_address_value(tmp_gopclntab_base, 7, 1);

			Address func_list_base=null;
			if(is_go116) {
				func_list_base=get_address(tmp_gopclntab_base, get_address_value(tmp_gopclntab_base, 8+tmp_pointer_size*6, tmp_pointer_size));
			}else {
				func_list_base=get_address(tmp_gopclntab_base, 8+tmp_pointer_size);
			}
			long func_addr_value=get_address_value(func_list_base, 0, tmp_pointer_size);
			long func_info_offset=get_address_value(func_list_base, tmp_pointer_size, tmp_pointer_size);
			long func_entry_value=0;
			if(is_go116) {
				func_entry_value=get_address_value(func_list_base, func_info_offset, tmp_pointer_size);
			}else {
				func_entry_value=get_address_value(tmp_gopclntab_base, func_info_offset, tmp_pointer_size);
			}

			if((tmp_quantum==1 || tmp_quantum==2 || tmp_quantum==4) && (tmp_pointer_size==4 || tmp_pointer_size==8) &&
					func_addr_value==func_entry_value && func_addr_value!=0) {
				break;
			}

			tmp_gopclntab_base=get_address(tmp_gopclntab_base, 4);
			if(tmp_gopclntab_base==null) {
				break;
			}
		}

		return tmp_gopclntab_base;
	}

	private boolean init_gopclntab() {
		if(this.gopclntab_base!=null) {
			return true;
		}

		this.gopclntab_base=search_gopclntab();
		if(this.gopclntab_base==null) {
			Logger.append_message("Failed to get gopclntab");
			return false;
		}

		this.magic=(int)get_address_value(gopclntab_base, 4);                                // magic
		                                                                                     // two zero bytes
		this.quantum=(int)get_address_value(gopclntab_base, 6, 1);                           // arch(x86=1, ?=2, arm=4)
		this.pointer_size=(int)get_address_value(gopclntab_base, 7, 1);                      // pointer size
		if((quantum!=1 && quantum!=2 && quantum!=4) ||
				(pointer_size!=4 && pointer_size!=8)) {
			Logger.append_message(String.format("Invalid gopclntab addr: %x", gopclntab_base.getOffset()));
			this.gopclntab_base=null;
			return false;
		}

		return true;
	}

	private boolean init_go_version()
	{
		go_version="";
		// cmd/go/internal/version/version.go
		// "\xff Go buildinf:"
		byte build_info_magic[]= {(byte)0xff,(byte)0x20,(byte)0x47,(byte)0x6f,(byte)0x20,(byte)0x62,(byte)0x75,(byte)0x69,(byte)0x6c,(byte)0x64,(byte)0x69,(byte)0x6e,(byte)0x66,(byte)0x3a};
		Address base_addr=null;
		base_addr=memory.findBytes(base_addr, build_info_magic, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff}, true, monitor);
		if(base_addr==null) {
			Logger.append_message("Failed to find \"\\xff Go buildinf:\"");
			return false;
		}

		byte size=(byte)get_address_value(base_addr, 14, 1);
		boolean is_big_endian=get_address_value(base_addr, 15, 1)!=0;
		if(is_big_endian) {
			Logger.append_message("Go version is big endian");
			return false;
		}

		go_version=read_string_struct(get_address_value(base_addr, 16, size), size);
		if(go_version==null)
		{
			go_version="";
			return false;
		}

		go_version_mod=read_string_struct(get_address_value(base_addr, 16+size, size), size);
		if(go_version_mod==null) {
			go_version_mod="";
		}
		else if(go_version_mod.length()>=33 && go_version_mod.charAt(go_version_mod.length()-17)=='\n')
		{
			go_version_mod=go_version_mod.substring(16, go_version_mod.length()-16);
		}
		else {
			go_version_mod="";
		}
		return true;
	}

	public int compare_go_version(String cmp_go_version) {
		String cmp1=cmp_go_version.substring(2);
		String cmp2=go_version.length()>2?go_version.substring(2):"0.0.0";
		String[] sp_cmp1=cmp1.split("\\.");
		String[] sp_cmp2=cmp2.split("\\.");

		int cmp1_major=0;
		int cmp2_major=0;
		if(sp_cmp1.length!=0) {
			cmp1_major=Integer.valueOf(sp_cmp1[0]);
		}
		if(sp_cmp2.length!=0) {
			cmp2_major=Integer.valueOf(sp_cmp2[0]);
		}
		if(cmp1_major>cmp2_major) {
			return 1;
		}else if(cmp1_major<cmp2_major) {
			return -1;
		}

		int cmp1_minor=0;
		int cmp1_patch=0;
		boolean cmp1_beta=false;
		boolean cmp1_rc=false;
		if(sp_cmp1.length>1 && sp_cmp1[1].contains("beta")) {
			cmp1_beta=true;
			String[] tmp=sp_cmp1[1].split("beta");
			if(tmp.length>1) {
				cmp1_minor=Integer.valueOf(tmp[0]);
				cmp1_patch=Integer.valueOf(tmp[1]);
			}
		}else if(sp_cmp1.length>1 && sp_cmp1[1].contains("rc")) {
			cmp1_rc=true;
			String[] tmp=sp_cmp1[1].split("rc");
			if(tmp.length>1) {
				cmp1_minor=Integer.valueOf(tmp[0]);
				cmp1_patch=Integer.valueOf(tmp[1]);
			}
		}else if(sp_cmp1.length>1) {
			cmp1_minor=Integer.valueOf(sp_cmp1[1]);
			if(sp_cmp1.length>2) {
				cmp1_patch=Integer.valueOf(sp_cmp1[2]);
			}
		}
		int cmp2_minor=0;
		int cmp2_patch=0;
		boolean cmp2_beta=false;
		boolean cmp2_rc=false;
		if(sp_cmp2.length>1 && sp_cmp2[1].contains("beta")) {
			cmp2_beta=true;
			String[] tmp=sp_cmp2[1].split("beta");
			if(tmp.length>1) {
				cmp2_minor=Integer.valueOf(tmp[0]);
				cmp2_patch=Integer.valueOf(tmp[1]);
			}
		}else if(sp_cmp2.length>1 && sp_cmp2[1].contains("rc")) {
			cmp2_rc=true;
			String[] tmp=sp_cmp2[1].split("rc");
			if(tmp.length>1) {
				cmp2_minor=Integer.valueOf(tmp[0]);
				cmp2_patch=Integer.valueOf(tmp[1]);
			}
		}else if(sp_cmp2.length>1) {
			cmp2_minor=Integer.valueOf(sp_cmp2[1]);
			if(sp_cmp2.length>2) {
				cmp2_patch=Integer.valueOf(sp_cmp2[2]);
			}
		}
		if(cmp1_minor>cmp2_minor) {
			return 1;
		}else if(cmp1_minor<cmp2_minor) {
			return -1;
		}
		if(!cmp1_beta && cmp2_beta) {
			return 1;
		}else if(cmp1_beta && !cmp2_beta) {
			return -1;
		}
		if(!cmp1_rc && cmp2_rc) {
			return 1;
		}else if(cmp1_rc && !cmp2_rc) {
			return -1;
		}
		if(cmp1_patch>cmp2_patch) {
			return 1;
		}else if(cmp1_patch<cmp2_patch) {
			return -1;
		}
		return 0;
	}
}
