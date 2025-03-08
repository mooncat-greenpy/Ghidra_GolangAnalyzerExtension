package golanganalyzerextension.gobinary;


import java.math.BigInteger;
import java.util.Optional;

import db.BooleanField;
import db.DBRecord;
import db.Field;
import db.IllegalFieldAccessException;
import db.IntField;
import db.LongField;
import db.Schema;
import db.StringField;
import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.disassemble.Disassembler;
import ghidra.program.disassemble.DisassemblerMessageListener;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressFormatException;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.Category;
import ghidra.program.model.data.CategoryPath;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeManager;
import ghidra.program.model.data.Integer16DataType;
import ghidra.program.model.data.Integer3DataType;
import ghidra.program.model.data.Integer5DataType;
import ghidra.program.model.data.Integer6DataType;
import ghidra.program.model.data.Integer7DataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.UnsignedInteger16DataType;
import ghidra.program.model.data.UnsignedInteger3DataType;
import ghidra.program.model.data.UnsignedInteger5DataType;
import ghidra.program.model.data.UnsignedInteger6DataType;
import ghidra.program.model.data.UnsignedInteger7DataType;
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
import golanganalyzerextension.GolangAnalyzerExtensionAnalyzer;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.exceptions.InvalidGolangVersionFormatException;
import golanganalyzerextension.gobinary.PcHeader.GO_VERSION;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;
import golanganalyzerextension.version.GolangVersion;
import golanganalyzerextension.version.GolangVersionExtractor;


public class GolangBinary {
	private Program program;
	private TaskMonitor monitor;
	private Listing program_listing;
	private Memory memory;

	private PcHeader pcheader;
	private ModuleData module_data;
	private GolangVersion go_version;
	private boolean guess_go_version;

	public GolangBinary(Program program, String custom_go_version_str, TaskMonitor monitor) {
		this.program=program;
		this.monitor=monitor;
		this.program_listing=program.getListing();
		this.memory=program.getMemory();

		pcheader=new PcHeader(this);
		GolangVersionExtractor go_version_extractor=new GolangVersionExtractor(this);
		guess_go_version=false;

		if (GolangVersion.is_go_version(custom_go_version_str)) {
			go_version=new GolangVersion(custom_go_version_str);
		} else if (go_version_extractor.scan()) {
			go_version=go_version_extractor.get_go_version();
		} else {
			go_version=GO_VERSION.to_go_version(pcheader.get_go_version());
			guess_go_version=true;
		}

		try {
			module_data=new ModuleData(this);
			if (!GolangVersion.is_go_version(custom_go_version_str) && !go_version_extractor.get_is_scanned_result() && go_version.le(module_data.get_go_version().get_version_str())) {
				go_version=module_data.get_go_version();
				guess_go_version=true;
			}
		} catch(InvalidBinaryStructureException e) {
			module_data=null;
			Logger.append_message(String.format("Failed to get module data: message=%s", e.getMessage()));
		}
	}

	public GolangBinary(Program program, String pcheader_addr_str, String custom_go_version_str, TaskMonitor monitor) {
		this.program=program;
		this.monitor=monitor;
		this.program_listing=program.getListing();
		this.memory=program.getMemory();

		Address pcheader_addr=null;
		try {
			pcheader_addr = get_address(pcheader_addr_str);
		} catch (BinaryAccessException e) {
		}
		if (pcheader_addr==null) {
			Logger.append_message(String.format("Invalid PcHeader address: addr=%s", pcheader_addr_str));
			return;
		}
		pcheader=new PcHeader(this, pcheader_addr);
		GolangVersionExtractor go_version_extractor=new GolangVersionExtractor(this);
		guess_go_version=false;

		if (GolangVersion.is_go_version(custom_go_version_str)) {
			go_version=new GolangVersion(custom_go_version_str);
		} else if (go_version_extractor.scan()) {
			go_version=go_version_extractor.get_go_version();
		} else {
			go_version=GO_VERSION.to_go_version(pcheader.get_go_version());
			guess_go_version=true;
		}

		try {
			module_data=new ModuleData(this);
			if (!GolangVersion.is_go_version(custom_go_version_str) && !go_version_extractor.get_is_scanned_result() && go_version.le(module_data.get_go_version().get_version_str())) {
				go_version=module_data.get_go_version();
				guess_go_version=true;
			}
		} catch(InvalidBinaryStructureException e) {
			module_data=null;
			Logger.append_message(String.format("Failed to get module data: message=%s", e.getMessage()));
		}
	}

	public GolangBinary(GolangBinary obj) {
		this.program=obj.program;
		this.monitor=obj.monitor;
		this.program_listing=obj.program_listing;
		this.memory=obj.memory;

		this.pcheader=obj.pcheader;
		this.go_version=obj.go_version;
		this.guess_go_version=obj.guess_go_version;
	}

	public static final int RECORD_KEY=0;
	private static final int RECORD_PCHEADER_ADDR_INDEX_V0=0;
	private static final int RECORD_PCHEADER_VERSION_INDEX_V0=1;
	private static final int RECORD_PCHEADER_LITTLE_ENDIAN_INDEX_V0=2;
	private static final int RECORD_GO_VERSION_INDEX_V0=3;
	public static final Schema SCHEMA_V0=new Schema(0, "GolangBinary",
			new Field[] {
					LongField.INSTANCE,
					IntField.INSTANCE,
					BooleanField.INSTANCE,
					StringField.INSTANCE,
					},
			new String[] {
					"PcheaderAddr",
					"PcheaderVersion",
					"PcheaderLittleEndian",
					"GoVersion",
					}
	);
	private static final int RECORD_GAE_VERSION_INDEX_V1=0;
	private static final int RECORD_PCHEADER_ADDR_INDEX_V1=1;
	private static final int RECORD_PCHEADER_VERSION_INDEX_V1=2;
	private static final int RECORD_PCHEADER_LITTLE_ENDIAN_INDEX_V1=3;
	private static final int RECORD_GO_VERSION_INDEX_V1=4;
	private static final int RECORD_GUESS_GO_VERSION_INDEX_V1=5;
	public static final Schema SCHEMA_V1=new Schema(1, "GolangBinary",
			new Field[] {
					StringField.INSTANCE,
					LongField.INSTANCE,
					IntField.INSTANCE,
					BooleanField.INSTANCE,
					StringField.INSTANCE,
					BooleanField.INSTANCE,
					},
			new String[] {
					"GAEVersion",
					"PcheaderAddr",
					"PcheaderVersion",
					"PcheaderLittleEndian",
					"GoVersion",
					"GuessGoVersion",
					}
	);

	public GolangBinary(Program program, TaskMonitor monitor, DBRecord record) throws IllegalArgumentException {
		this.program=program;
		this.monitor=monitor;
		this.program_listing=program.getListing();
		this.memory=program.getMemory();

		long pcheader_addr_value;
		int pcheader_version_num;
		boolean pcheader_little_endian;
		String go_version_str;
		boolean guess_go_version_flag=false;

		if(record.hasSameSchema(SCHEMA_V0)) {
			try {
				pcheader_addr_value=record.getLongValue(RECORD_PCHEADER_ADDR_INDEX_V0);
				pcheader_version_num=record.getIntValue(RECORD_PCHEADER_VERSION_INDEX_V0);
				pcheader_little_endian=record.getBooleanValue(RECORD_PCHEADER_LITTLE_ENDIAN_INDEX_V0);
				go_version_str=record.getString(RECORD_GO_VERSION_INDEX_V0);
			} catch(IllegalFieldAccessException e) {
				throw new IllegalArgumentException(String.format("Invalid DBRecord field: message=%s", e.getMessage()));
			}
		} else if(record.hasSameSchema(SCHEMA_V1)) {
			try {
				pcheader_addr_value=record.getLongValue(RECORD_PCHEADER_ADDR_INDEX_V1);
				pcheader_version_num=record.getIntValue(RECORD_PCHEADER_VERSION_INDEX_V1);
				pcheader_little_endian=record.getBooleanValue(RECORD_PCHEADER_LITTLE_ENDIAN_INDEX_V1);
				go_version_str=record.getString(RECORD_GO_VERSION_INDEX_V1);
				guess_go_version_flag=record.getBooleanValue(RECORD_GUESS_GO_VERSION_INDEX_V1);
			} catch(IllegalFieldAccessException e) {
				throw new IllegalArgumentException(String.format("Invalid DBRecord field: message=%s", e.getMessage()));
			}
		} else {
			throw new IllegalArgumentException("Invalid DBRecord schema");
		}
		try {
			this.pcheader=new PcHeader(this, get_address(pcheader_addr_value), GO_VERSION.from_integer(pcheader_version_num), pcheader_little_endian, false);
			this.go_version=new GolangVersion(go_version_str);
			this.guess_go_version=guess_go_version_flag;
		} catch(InvalidBinaryStructureException | BinaryAccessException | InvalidGolangVersionFormatException e) {
			throw new IllegalArgumentException(String.format("Invalid GolangBinary arg: pcheader_addr=%x, pcheader_version=%x, go_version=%s, message=%s", pcheader_addr_value, pcheader_version_num, go_version_str, e.getMessage()));
		}
	}

	public DBRecord get_record() throws IllegalFieldAccessException {
		DBRecord record=SCHEMA_V1.createRecord(RECORD_KEY);
		record.setString(RECORD_GAE_VERSION_INDEX_V1, GolangAnalyzerExtensionAnalyzer.VERSION);
		record.setLongValue(RECORD_PCHEADER_ADDR_INDEX_V1, pcheader.get_addr().getOffset());
		record.setIntValue(RECORD_PCHEADER_VERSION_INDEX_V1, GO_VERSION.to_integer(pcheader.get_go_version()));
		record.setBooleanValue(RECORD_PCHEADER_LITTLE_ENDIAN_INDEX_V1, pcheader.is_little_endian());
		record.setString(RECORD_GO_VERSION_INDEX_V1, go_version.get_version_str());
		record.setBooleanValue(RECORD_GUESS_GO_VERSION_INDEX_V1, guess_go_version);
		return record;
	}

	public Program get_program() {
		return program;
	}

	public String get_name() {
		return program.getName();
	}

	public Address get_address(Address base, long offset) throws BinaryAccessException {
		if(base==null) {
			return null;
		}
		try {
			return base.add(offset);
		}catch(AddressOutOfBoundsException e) {
			throw new BinaryAccessException(String.format("Get address: addr=%x+%x, message=%s", base.getOffset(), offset, e.getMessage()));
		}
	}

	public Address get_address(long addr_value) throws BinaryAccessException {
		try {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_value);
		}catch(AddressOutOfBoundsException e) {
			throw new BinaryAccessException(String.format("Get address: addr=%x, message=%s", addr_value, e.getMessage()));
		}
	}

	public Address get_address(String addr_str) throws BinaryAccessException {
		try {
			return program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_str);
		} catch (AddressFormatException e) {
			throw new BinaryAccessException(String.format("Get address: addr=%s, message=%s", addr_str, e.getMessage()));
		}
	}

	public boolean is_valid_address(Address addr) {
		if(addr==null) {
			return false;
		}
		boolean ret=false;
		try {
			memory.getByte(addr);
			ret=true;
		} catch (MemoryAccessException e) {
			ret=false;
		}
		return ret;
	}

	public boolean is_valid_address(Address addr, long size) {
		if(size<1) {
			size=1;
		}
		if(!is_valid_address(addr)) {
			return false;
		}
		try {
			if(!is_valid_address(get_address(addr, size-1))) {
				return false;
			}
			for(int i=0; i<size; i+=get_pointer_size()) {
				if(!is_valid_address(get_address(addr, i))) {
					return false;
				}
			}
		} catch (BinaryAccessException e) {
			return false;
		}

		return true;
	}

	public boolean is_valid_address(long addr_value) {
		try {
			return is_valid_address(get_address(addr_value));
		} catch (BinaryAccessException e) {
			return false;
		}
	}

	public boolean is_valid_address(long addr_value, long size) {
		try {
			return is_valid_address(get_address(addr_value), size);
		} catch (BinaryAccessException e) {
			return false;
		}
	}

	public long get_address_value(Address addr, int size) throws BinaryAccessException {
		if(addr==null) {
			throw new BinaryAccessException(String.format("Get addr value: addr=%s, size=%x", addr, size));
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
			throw new BinaryAccessException(String.format("Get addr value: addr=%s, size=%x, message=%s", addr, size, e.getMessage()));
		}
	}

	public long get_address_value(long addr_value, int size) throws BinaryAccessException {
		return get_address_value(get_address(addr_value), size);
	}

	public long get_address_value(Address addr, long offset, int size) throws BinaryAccessException {
		if(addr==null) {
			throw new BinaryAccessException(String.format("Get addr value: addr=%s+%x, size=%x", addr, offset, size));
		}
		return get_address_value(get_address(addr, offset), size);
	}

	public Optional<Address> find_memory(Address base_addr, byte[] target, byte[] mask) {
		return Optional.ofNullable(memory.findBytes(base_addr, target, mask, true, monitor));
	}

	public Optional<Address> get_section(String name) {
		for (MemoryBlock mb : memory.getBlocks()) {
			if(mb.getName().equals(name)) {
				return Optional.ofNullable(mb.getStart());
			}
		}
		return Optional.empty();
	}

	public Optional<Structure> get_datatype(String path, String name) {
		DataTypeManager datatype_manager=program.getDataTypeManager();
		CategoryPath category_path=new CategoryPath(path);
		if(!datatype_manager.containsCategory(category_path)) {
			return Optional.empty();
		}
		Category category=datatype_manager.getCategory(category_path);
		// ghidra.program.database.data.StructureDB
		return Optional.ofNullable((Structure)category.getDataType(name));
	}

	public void add_datatype(String path, DataType datatype) {
		DataTypeManager datatype_manager=program.getDataTypeManager();
		CategoryPath category_path=new CategoryPath(path);
		Category category;
		if(datatype_manager.containsCategory(category_path)) {
			category=datatype_manager.getCategory(category_path);
		} else {
			category=datatype_manager.createCategory(category_path);
		}
		category.addDataType(datatype, null);
	}


	public DataType get_unsigned_numeric_datatype(int size) throws InvalidBinaryStructureException {
		if(size==1) {
			return new ByteDataType();
		}else if(size==2) {
			return new UnsignedShortDataType();
		}else if(size==3) {
			return new UnsignedInteger3DataType();
		}else if(size==4) {
			// The size of UnsignedIntegerDataType and UnsignedLongDataType depends on the binary.
			return new UnsignedInteger4DataType();
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
		}

		throw new InvalidBinaryStructureException("Invalid datatype size");
	}

	public DataType get_signed_numeric_datatype(int size) throws InvalidBinaryStructureException {
		if(size==1) {
			return new SignedByteDataType();
		}else if(size==2) {
			return new ShortDataType();
		}else if(size==3) {
			return new Integer3DataType();
		}else if(size==4) {
			// The size of UnsignedIntegerDataType and UnsignedLongDataType depends on the binary.
			return new Integer4DataType();
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
		}

		throw new InvalidBinaryStructureException("Invalid datatype size");
	}

	public MemoryBlock[] get_memory_blocks() {
		return memory.getBlocks();
	}

	public void clear_data(Address addr, long size) {
		if(size<1) {
			size=1;
		}
		Address addr_end=null;
		for(long i=size; i>0; i--) {
			try {
				addr_end=get_address(addr, i-1);
				break;
			} catch (BinaryAccessException e) {
			}
		}
		if(addr_end==null) {
			addr_end=addr;
		}
		program_listing.clearCodeUnits(addr, addr_end, false);
	}

	public String read_string(Address addr, int size) throws BinaryAccessException, InvalidBinaryStructureException {
		if(size>0x1000 || size<=0) {
			throw new InvalidBinaryStructureException(String.format("Too large string size: addr=%s, size=%d", addr, size));
		}
		try {
			byte[] bytes=new byte[size];
			memory.getBytes(addr, bytes, 0, size);
			String str=new String(bytes);
			str=str.replaceAll("[^\\x09\\x0a\\x0d\\x20-\\x7e]", "");
			return str;
		} catch (MemoryAccessException e) {
			throw new BinaryAccessException(String.format("Get string: addr=%s, size=%d, message=%s", addr, size, e.getMessage()));
		}
	}

	public String read_string_struct(Address string_struct_addr, int value_size) throws InvalidBinaryStructureException {
		try {
			Address string_addr=get_address(get_address_value(string_struct_addr, value_size));
			long string_size=get_address_value(string_struct_addr, value_size, value_size);
			return read_string(string_addr, (int)string_size);
		} catch (BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Get string struct: addr=%s, field_size=%x", string_struct_addr, value_size));
		}
	}

	public String read_string_struct(long string_struct_addr_value, int value_size) throws InvalidBinaryStructureException {
		try {
			Address addr=get_address(string_struct_addr_value);
			return read_string_struct(addr, value_size);
		} catch (BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Get string struct: addr=%x, field_size=%x", string_struct_addr_value, value_size));
		}
	}

	public Optional<String> create_string_data(Address addr, int size) {
		clear_data(addr, size);
		Data string_data=null;
		try {
			string_data=program_listing.createData(addr, new StringDataType(), size);
		} catch (CodeUnitInsertionException e) {
			Logger.append_message(String.format("Failed to create string data: %s %x", e.getMessage(), addr.getOffset()));
		}
		if(string_data==null || !string_data.getDataType().isEquivalent((new StringDataType()))) {
			return Optional.empty();
		}

		return Optional.ofNullable((String)string_data.getValue());
	}

	public Optional<String> create_string_data(Address addr) {
		clear_data(addr, 1);
		Data string_data=null;
		try {
			string_data=program_listing.createData(addr, new StringDataType());
			if(!string_data.getDataType().isEquivalent((new StringDataType()))) {
				return Optional.empty();
			}
		} catch (CodeUnitInsertionException e) {
			Logger.append_message(String.format("Failed to create string data: %s addr=%x", e.getMessage(), addr.getOffset()));
		}

		if(string_data==null) {
			Address zero_addr=memory.findBytes(addr, new byte[] {(byte)0x0}, new byte[] {(byte)0xff}, true, monitor);
			if(zero_addr==null) {
				return Optional.empty();
			}
			int size=(int)(zero_addr.getOffset()-addr.getOffset());
			try {
				return Optional.ofNullable(read_string(addr, size));
			} catch (BinaryAccessException e) {
				return Optional.empty();
			}
		}
		return Optional.of((String)string_data.getValue());
	}

	public void create_data(Address addr, DataType datatype) throws BinaryAccessException {
		clear_data(addr, datatype.getLength());
		try {
			program.getListing().createData(addr, datatype);
		} catch (CodeUnitInsertionException e) {
			throw new BinaryAccessException(String.format("Create data: addr=%s, datatype=%s, message=%s", addr, datatype, e.getMessage()));
		}
	}

	public Optional<Function> get_function(Address addr) {
		return Optional.ofNullable(program.getFunctionManager().getFunctionAt(addr));
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

	public boolean is_ppc() {
		return program.getLanguage().getProcessor().toString().equals("PowerPC");
	}

	public boolean is_riscv() {
		return program.getLanguage().getProcessor().toString().equals("RISCV");
	}

	public void disassemble(Address addr, long size) throws BinaryAccessException {
		Address addr_end=get_address(addr, size);

		clear_data(addr, size);
		Address target=addr;
		Disassembler disassembler=Disassembler.getDisassembler(program, monitor, new DisassemblerMessageListener() {
			@Override
			public void disassembleMessageReported(String msg) {
				Logger.append_message(msg);
			}
		});
		AddressSet addr_set=new AddressSet(program, addr, addr_end);
		while(target.getOffset()<addr_end.getOffset()) {
			disassembler.disassemble(target, addr_set, true);
			Instruction inst=get_instruction(target).orElse(null);
			if (inst==null) {
				return;
			}
			target=get_address(target, inst.getLength());
		}
	}

	public Optional<Instruction> get_instruction(Address addr) {
		return Optional.ofNullable(program_listing.getInstructionAt(addr));
	}

	public boolean is_ret_inst(Instruction inst) {
		if(inst.toString().toUpperCase().contains("RET") || inst.toString().toLowerCase().equals("add pc,lr,#0x0")) {
			return true;
		}
		return false;
	}

	public Optional<Register> get_register(String reg_str) {
		return Optional.ofNullable(program.getRegister(reg_str));
	}

	public Optional<BigInteger> get_register_value(Register reg, Address addr) {
		return Optional.ofNullable(program.getProgramContext().getRegisterValue(reg, addr).getSignedValue());
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

	public void create_label(Address addr, String str) throws BinaryAccessException {
		try {
			str=str.replaceAll("[ \n\t]", "_");
			program.getSymbolTable().createLabel(addr, str, ghidra.program.model.symbol.SourceType.USER_DEFINED);
		} catch (IllegalArgumentException | InvalidInputException e) {
			throw new BinaryAccessException(String.format("Create label: addr=%s, label=%s", addr, str));
		}
	}

	public void set_comment(Address addr, int type, String comment) throws BinaryAccessException {
		try {
			program.getListing().setComment(addr, type, comment);
		} catch (IllegalArgumentException e) {
			throw new BinaryAccessException(String.format("Set comment: addr=%s, type=%x, comment=%s", addr, type, comment));
		}
	}

	public Optional<Address> get_text_base() {
		MemoryBlock text_section=null;
		MemoryBlock func_section=null;
		Address first_func_addr=null;
		FunctionIterator func_iter=get_functions();
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

	public Address get_pcheader_base() {
		return pcheader.get_addr();
	}

	public int get_pointer_size() {
		return pcheader.get_pointer_size();
	}

	public int get_quantum() {
		return pcheader.get_quantum();
	}

	public boolean is_little_endian() {
		return pcheader.is_little_endian();
	}

	public Optional<ModuleData> get_module_data() {
		return Optional.ofNullable(module_data);
	}

	public String get_go_version() {
		return go_version.get_version_str();
	}

	public boolean get_guess_go_version() {
		return guess_go_version;
	}

	public boolean eq_go_version(String cmp_go_version) throws InvalidGolangVersionFormatException {
		return go_version.eq(cmp_go_version);
	}

	public boolean gt_go_version(String cmp_go_version) throws InvalidGolangVersionFormatException {
		return go_version.gt(cmp_go_version);
	}

	public boolean lt_go_version(String cmp_go_version) throws InvalidGolangVersionFormatException {
		return go_version.lt(cmp_go_version);
	}

	public boolean ge_go_version(String cmp_go_version) throws InvalidGolangVersionFormatException {
		return go_version.ge(cmp_go_version);
	}

	public boolean le_go_version(String cmp_go_version) throws InvalidGolangVersionFormatException {
		return go_version.le(cmp_go_version);
	}

	public void set_go_version(String str) {
		go_version.set_version_str(str);
	}
}
