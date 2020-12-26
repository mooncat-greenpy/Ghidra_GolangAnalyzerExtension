package golanganalyzerextension;

import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Function.FunctionUpdateType;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.ParameterImpl;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.Memory;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.mem.MemoryBlock;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.exception.CancelledException;
import ghidra.util.exception.DuplicateNameException;
import ghidra.util.exception.InvalidInputException;
import ghidra.util.task.TaskMonitor;
import ghidra.program.model.data.*;

/**
 * TODO: Provide class-level documentation that describes what this analyzer does.
 */
public class GolangAnalyzerExtensionAnalyzer extends AbstractAnalyzer {
	public GolangAnalyzerExtensionAnalyzer() {

		// TODO: Name the analyzer and give it a description.

		super("My Analyzer", "Analyzer description goes here", AnalyzerType.BYTE_ANALYZER);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		// TODO: Return true if analyzer should be enabled by default

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		// TODO: Examine 'program' to determine of this analyzer should analyze it.  Return true
		// if it can.

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		// TODO: If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		// TODO: Perform analysis when things get added to the 'program'.  Return true if the
		// analysis succeeded.

		int pointer_size=get_pointer_size(program);

		Memory memory=program.getMemory();

		Address base=get_gopclntab(program, monitor);
		if(base==null)
		{
			log.appendMsg("gopclntab not found");
			return false;
		}
		int func_num=0;
		try {
			// magic, two zero bytes, arch(x86=1, arm=4), uintptr size
			pointer_size=(int)get_address_value(memory, base.add(7), 1);
			func_num=(int)get_address_value(memory, base.add(8), 4);
		}catch(MemoryAccessException e) {
			log.appendException(e);
			return false;
		}
		List<String> file_name_list=get_file_list(program, base, func_num, pointer_size);
		Address func_list_base=base.add(8+pointer_size);
		for(int i=0; i<func_num; i++) {
			long func_addr_value=0;
			long func_info_offset=0;
			int func_name_offset=0;
			int args=0;
			try {
				func_addr_value=get_address_value(memory, func_list_base.add(i*pointer_size*2), pointer_size);
				func_info_offset=get_address_value(memory, func_list_base.add(i*pointer_size*2+pointer_size), pointer_size);
				long func_entry_value=memory.getInt(base.add(func_info_offset));
				func_name_offset=memory.getInt(base.add(func_info_offset+pointer_size));
				args=memory.getInt(base.add(func_info_offset+pointer_size+4));

				if(func_addr_value!=func_entry_value)
				{
					log.appendMsg(String.format("Wrong func addr %x %x", func_addr_value, func_entry_value));
					continue;
				}

				String func_name=create_function_name_data(program, base.add(func_name_offset));
				if(func_name==null) {
					log.appendMsg("The type of func name data is not String");
					continue;
				}

				rename_function(program, monitor, func_addr_value, func_name);
				modify_function(program, func_addr_value, args);
			}catch(Exception e) {
				log.appendException(e);
			}
		}

		return false;
	}

	int get_pointer_size(Program program) {
		if(program.getLanguageID().getIdAsString().contains("LE:64")) {
			return 8;
		}
		return 4;
	}

	long get_address_value(Memory memory, Address address, int size) throws MemoryAccessException {
		if(size==8) {
			return memory.getLong(address);
		}else if(size==4) {
			return memory.getInt(address);
		}
		return memory.getByte(address)&0xff;
	}

	Address get_gopclntab(Program program, TaskMonitor monitor) {
		MemoryBlock gopclntab_section=null;
		for (MemoryBlock mb : program.getMemory().getBlocks()) {
			if(mb.getName().equals(".gopclntab")) {
				gopclntab_section=mb;
			}
		}
		if(gopclntab_section!=null) {
			return gopclntab_section.getStart();
		}

		byte magic[]= {(byte)0xfb,(byte)0xff,(byte)0xff,(byte)0xff};
		Address base=null;
		while(true) {
			base=program.getMemory().findBytes(base, magic, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff}, true, monitor);
			if(base==null) {
				break;
			}

			int pointer_size=get_pointer_size(program);
			Memory memory=program.getMemory();
			Address func_list_base=base.add(8+pointer_size);
			try {
				long func_addr_value=get_address_value(memory, func_list_base.add(0), pointer_size);
				long func_info_offset=get_address_value(memory, func_list_base.add(pointer_size), pointer_size);
				long func_entry_value=memory.getInt(base.add(func_info_offset));
				if(func_addr_value==func_entry_value)
				{
					break;
				}
			}catch(MemoryAccessException e) {
			}
			base=base.add(4);
		}

		return base;
	}

	String create_function_name_data(Program program, Address address) throws CodeUnitInsertionException {
		Listing listing=program.getListing();
		Data func_name_data=listing.getDefinedDataAt(address);
		if(func_name_data==null) {
			func_name_data=listing.createData(address, new StringDataType());
		}else if(!func_name_data.getDataType().isEquivalent((new StringDataType()))) {
			return null;
		}
		return (String)func_name_data.getValue();
	}

	void rename_function(Program program, TaskMonitor monitor, long func_addr_value, String func_name) throws DuplicateNameException, InvalidInputException {
		Address func_addr=program.getAddressFactory().getDefaultAddressSpace().getAddress(func_addr_value);
		Function func=program.getFunctionManager().getFunctionAt(func_addr);
		if(func==null) {
			CreateFunctionCmd cmd=new CreateFunctionCmd(func_name, func_addr, null, SourceType.ANALYSIS);
			cmd.applyTo(program, monitor);
			return;
		}else if(func.getName().equals(func_name)) {
			return;
		}
		func.setName(func_name, SourceType.ANALYSIS);
	}

	void modify_function(Program program, long func_addr_value, int args_num) {
		Address func_addr=program.getAddressFactory().getDefaultAddressSpace().getAddress(func_addr_value);
		Function func=program.getFunctionManager().getFunctionAt(func_addr);
		int pointer_size=get_pointer_size(program);
		if(func==null) {
			return;
		}
		if(func.getParameterCount()==args_num/pointer_size) {
			return;
		}

		try {
			List<Parameter> new_params=new ArrayList<>();
			for(int i=0;i<args_num/pointer_size;i++) {
				DataType data_type=null;
				if(i<func.getParameterCount()) {
					data_type=func.getParameter(i).getDataType();
				}else if(pointer_size==8) {
					data_type=new Undefined8DataType();
				}else {
					data_type=new Undefined4DataType();
				}
				Parameter param=new ParameterImpl(String.format("param_%d", i+1), data_type, (i+1)*pointer_size, func.getProgram(), SourceType.USER_DEFINED);
				new_params.add(param);
			}

			func.updateFunction(null, null, new_params, FunctionUpdateType.CUSTOM_STORAGE, true, SourceType.USER_DEFINED);
		}catch(Exception e) {
		}
	}

	List<String> get_file_list(Program program, Address base, int func_num, int pointer_size) {
		Memory memory=program.getMemory();
		Address func_list_base=base.add(8+pointer_size);
		List<String> file_name_list=new ArrayList<>();
		try {
			long file_name_table_offset=get_address_value(memory, func_list_base.add(func_num*pointer_size*2+pointer_size), pointer_size);
			Address file_name_table=base.add(file_name_table_offset);
			long file_name_table_size=get_address_value(memory, file_name_table, 4);
			for(int i=1;i<file_name_table_size;i++) {
				long file_name_offset=get_address_value(memory, file_name_table.add(4*i),4);
				String file_name=create_function_name_data(program, base.add(file_name_offset));
				file_name_list.add(file_name);
			}
		}catch(Exception e) {
		}
		return file_name_list;
	}

}
