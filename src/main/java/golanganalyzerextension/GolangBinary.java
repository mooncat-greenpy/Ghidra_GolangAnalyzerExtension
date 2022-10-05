package golanganalyzerextension;


import java.math.BigInteger;
import java.util.Optional;

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

	private GolangVersion go_version;

	public GolangBinary(Program program, TaskMonitor monitor) {
		this.program=program;
		this.monitor=monitor;
		this.program_listing=program.getListing();
		this.memory=program.getMemory();

		GolangVersionExtractor go_version_extractor=new GolangVersionExtractor(this);
		go_version_extractor.scan();
		go_version=go_version_extractor.get_go_version();

		if(!init_gopclntab()) {
			Logger.append_message("Failed to init gopclntab");
			return;
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

		this.ok=true;
	}

	public GolangBinary(GolangBinary obj, Program program, TaskMonitor monitor, Listing program_listing, Memory memory, Address gopclntab_base, int magic, int quantum, int pointer_size, GolangVersion go_version) {
		if(program==null) {
			this.program=obj.program;
		} else {
			this.program=program;
		}
		if(monitor==null) {
			this.monitor=obj.monitor;
		} else {
			this.monitor=monitor;
		}
		if(program_listing==null) {
			this.program_listing=obj.program_listing;
		} else {
			this.program_listing=program_listing;
		}
		if(memory==null) {
			this.memory=obj.memory;
		} else {
			this.memory=memory;
		}

		if(gopclntab_base==null) {
			this.gopclntab_base=obj.gopclntab_base;
		} else {
			this.gopclntab_base=gopclntab_base;
		}
		if(magic==0) {
			this.magic=obj.magic;
		} else {
			this.magic=magic;
		}
		if(quantum==0) {
			this.quantum=obj.quantum;
		} else {
			this.quantum=quantum;
		}
		if(pointer_size==0) {
			this.pointer_size=obj.pointer_size;
		} else {
			this.pointer_size=pointer_size;
		}
		if(go_version==null) {
			this.go_version=obj.go_version;
		} else {
			this.go_version=go_version;
		}

		this.ok=true;
	}

	public boolean is_ok() {
		return ok;
	}

	public String get_name() {
		return program.getName();
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

	public long get_address_value(long addr_value, int size) {
		return get_address_value(get_address(addr_value), size);
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

	public Address get_section(String name) {
		for (MemoryBlock mb : memory.getBlocks()) {
			if(mb.getName().equals(name)) {
				return mb.getStart();
			}
		}
		return null;
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
			String str=new String(bytes);
			int tmp_len=str.length();
			str=str.replaceAll("[^\\x20-\\x7e]", "");
			if(str.length()!=tmp_len) {
				Logger.append_message(String.format("Invalid char: %x %x %s", addr.getOffset(), size, str));
			}
			return str;
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

	public Optional<Address> get_text_base() {
		MemoryBlock text_section=null;
		MemoryBlock func_section=null;
		Address first_func_addr=null;
		FunctionIterator func_iter=program.getFunctionManager().getFunctions(true);
		if(func_iter.hasNext()) {
			first_func_addr=func_iter.next().getEntryPoint();
		}
		for (MemoryBlock mb : memory.getBlocks()) {
			if(mb.getName().equals(".text")) {
				text_section=mb;
			}
			if(first_func_addr!=null && mb.getStart().getOffset()<=first_func_addr.getOffset() && first_func_addr.getOffset()<mb.getEnd().getOffset()) {
				func_section=mb;
			}
		}
		if(text_section!=null) {
			return Optional.ofNullable(text_section.getStart());
		}
		if(func_section!=null) {
			return Optional.ofNullable(func_section.getStart());
		}
		return Optional.empty();
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
		boolean is_go118=false;
		if(ge_go_version("go1.16beta1")) {
			is_go116=true;
			go12_magic[0]=(byte)0xfa;
		}
		if(ge_go_version("go1.18beta1")) {
			is_go118=true;
			go12_magic[0]=(byte)0xf0;
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
			if(is_go118) {
				func_list_base=get_address(tmp_gopclntab_base, get_address_value(tmp_gopclntab_base, 8+tmp_pointer_size*7, tmp_pointer_size));
			}else if(is_go116) {
				func_list_base=get_address(tmp_gopclntab_base, get_address_value(tmp_gopclntab_base, 8+tmp_pointer_size*6, tmp_pointer_size));
			}else {
				func_list_base=get_address(tmp_gopclntab_base, 8+tmp_pointer_size);
			}
			long func_addr_value=get_address_value(func_list_base, 0, is_go118?4:tmp_pointer_size);
			long func_info_offset=get_address_value(func_list_base, is_go118?4:tmp_pointer_size, is_go118?4:tmp_pointer_size);
			long func_entry_value=0;
			if(is_go118) {
				func_entry_value=get_address_value(func_list_base, func_info_offset, 4);
			}if(is_go116) {
				func_entry_value=get_address_value(func_list_base, func_info_offset, tmp_pointer_size);
			}else {
				func_entry_value=get_address_value(tmp_gopclntab_base, func_info_offset, tmp_pointer_size);
			}

			if((tmp_quantum==1 || tmp_quantum==2 || tmp_quantum==4) && (tmp_pointer_size==4 || tmp_pointer_size==8) &&
					func_addr_value==func_entry_value && (is_go118 || func_addr_value!=0)) {
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

	public String get_go_version() {
		return go_version.get_version_str();
	}

	public boolean eq_go_version(String cmp_go_version) {
		return go_version.eq(cmp_go_version);
	}

	public boolean gt_go_version(String cmp_go_version) {
		return go_version.gt(cmp_go_version);
	}

	public boolean lt_go_version(String cmp_go_version) {
		return go_version.lt(cmp_go_version);
	}

	public boolean ge_go_version(String cmp_go_version) {
		return go_version.ge(cmp_go_version);
	}

	public boolean le_go_version(String cmp_go_version) {
		return go_version.le(cmp_go_version);
	}
}
