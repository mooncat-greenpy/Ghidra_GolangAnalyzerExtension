package golanganalyzerextension;


import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.task.TaskMonitor;

public class GolangBinary {
	Program program=null;
	TaskMonitor monitor=null;
	MessageLog log=null;
	Listing program_listing=null;
	Memory memory=null;

	public GolangBinary(Program program, TaskMonitor monitor, MessageLog log) {
		this.program=program;
		this.monitor=monitor;
		this.log=log;
		this.program_listing=program.getListing();
		this.memory=program.getMemory();
	}

	long get_address_value(Address address, int size) {
		try {
			if(size==8) {
				return memory.getLong(address);
			}else if(size==4) {
				return memory.getInt(address);
			}
			return memory.getByte(address)&0xff;
		}catch(MemoryAccessException e) {
			log.appendMsg(String.format("Failed get address value: %s", e.getMessage()));
		}
		return 0;
	}

	String create_string_data(Address address){
		Data string_data=program_listing.getDefinedDataAt(address);
		if(string_data==null) {
			try {
				string_data=program_listing.createData(address, new StringDataType());
			} catch (CodeUnitInsertionException | DataTypeConflictException e) {
				log.appendMsg(String.format("Failed create_string_data: %s %x", e.getMessage(), address.getOffset()));
			}
		}else if(!string_data.getDataType().isEquivalent((new StringDataType()))) {
			return "not found";
		}
		if(string_data==null) {
			try {
				Address zero_addr=memory.findBytes(address, new byte[] {(byte)0x0}, new byte[] {(byte)0xff}, true, monitor);
				if(zero_addr==null) {
					return "not found";
				}
				int size=(int)(zero_addr.getOffset()-address.getOffset());
				byte[] bytes=new byte[size];
				memory.getBytes(address, bytes, 0, size);
				return new String(bytes);
			} catch (MemoryAccessException e) {
				log.appendMsg(String.format("Failed read bytes string: %s %x", e.getMessage(), address.getOffset()));
			}
			return "not found";
		}
		return (String)string_data.getValue();
	}
}
