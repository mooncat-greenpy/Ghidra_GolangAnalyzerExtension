package golanganalyzerextension;


import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;

public class GolangBinary {
	Program program=null;
	TaskMonitor monitor=null;
	MessageLog log=null;
	Listing program_listing=null;
	Memory memory=null;
	boolean ok=false;
	boolean debugmode=false;

	public GolangBinary(Program program, TaskMonitor monitor, MessageLog log, boolean debugmode) {
		this.program=program;
		this.monitor=monitor;
		this.log=log;
		this.program_listing=program.getListing();
		this.memory=program.getMemory();
		this.ok=false;
		this.debugmode=debugmode;
	}

	Address get_address(Address base, long offset) {
		if(base==null) {
			return null;
		}
		try {
			return base.add(offset);
		}catch(AddressOutOfBoundsException e) {
			append_message(String.format("Failed to get address: %s %x+%x", e.getMessage(), base.getOffset(), offset));
		}
		return null;
	}

	long get_address_value(Address address, int size) {
		if(address==null) {
			return 0;
		}
		try {
			if(size==8) {
				return memory.getLong(address);
			}else if(size==4) {
				return memory.getInt(address);
			}else if(size==2) {
				return memory.getShort(address);
			}
			return memory.getByte(address)&0xff;
		}catch(MemoryAccessException e) {
			append_message(String.format("Failed to get value: %s %x", e.getMessage(), address.getOffset()));
		}
		return 0;
	}

	String read_string(Address address, int size) {
		try {
			byte[] bytes=new byte[size];
			memory.getBytes(address, bytes, 0, size);
			return new String(bytes);
		} catch (MemoryAccessException e) {
			append_message(String.format("Failed to read string: %s %x", e.getMessage(), address.getOffset()));
		}
		return "not found";
	}

	String create_string_data(Address address){
		if(address==null) {
			return "not found";
		}
		Data string_data=program_listing.getDefinedDataAt(address);
		if(string_data==null) {
			try {
				string_data=program_listing.createData(address, new StringDataType());
			} catch (CodeUnitInsertionException | DataTypeConflictException e) {
				append_message(String.format("Failed to create string data: %s %x", e.getMessage(), address.getOffset()));
			}
		}else if(!string_data.getDataType().isEquivalent((new StringDataType()))) {
			return "not found";
		}
		if(string_data==null) {
			Address zero_addr=memory.findBytes(address, new byte[] {(byte)0x0}, new byte[] {(byte)0xff}, true, monitor);
			if(zero_addr==null) {
				return "not found";
			}
			int size=(int)(zero_addr.getOffset()-address.getOffset());
			return read_string(address, size);
		}
		return (String)string_data.getValue();
	}

	void create_label(Address address, String str) {
		try {
			str=str.replace(" ", "_");
			program.getSymbolTable().createLabel(address, str, ghidra.program.model.symbol.SourceType.USER_DEFINED);
		} catch (InvalidInputException e) {
			append_message(String.format("Failed to create label: %x %s", address.getOffset(), str));
		}
	}

	void append_message(String str) {
		if(debugmode) {
			log.appendMsg(str);
		}
	}

	boolean is_ok() {
		return ok;
	}
}
