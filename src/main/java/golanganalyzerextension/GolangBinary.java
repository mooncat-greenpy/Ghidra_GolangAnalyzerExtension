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
import ghidra.program.model.mem.MemoryBlock;
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
	Address gopclntab_base=null;
	int magic=0;
	int quantum=0;
	int pointer_size=0;
	String go_version="";
	String go_version_mod="";

	public GolangBinary(Program program, TaskMonitor monitor, MessageLog log, boolean debugmode) {
		this.program=program;
		this.monitor=monitor;
		this.log=log;
		this.program_listing=program.getListing();
		this.memory=program.getMemory();
		this.ok=false;
		this.debugmode=debugmode;
	}

	public GolangBinary(GolangBinary obj) {
		this.program=obj.program;
		this.monitor=obj.monitor;
		this.log=obj.log;
		this.program_listing=obj.program_listing;
		this.memory=obj.memory;
		this.ok=false;
		this.debugmode=obj.debugmode;

		this.gopclntab_base=obj.gopclntab_base;
		this.magic=obj.magic;
		this.quantum=obj.quantum;
		this.pointer_size=obj.pointer_size;
		this.go_version=obj.go_version;
		this.go_version_mod=obj.go_version_mod;
	}

	boolean is_valid_address(Address addr) {
		boolean ret=false;
		try {
			memory.getByte(addr);
			ret=true;
		} catch (MemoryAccessException e) {
			ret=false;
		}
		return ret;
	}

	boolean is_valid_address(long addr_value) {
		return is_valid_address(program.getAddressFactory().getAddress(String.format("%x", addr_value)));
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

	String read_string_struct(Address string_struct_addr, int value_size) {
		if(!is_valid_address(string_struct_addr)) {
			return null;
		}
		Address string_addr=program.getAddressFactory().getAddress(
				String.format("%x", get_address_value(string_struct_addr, value_size)));
		if(!is_valid_address(string_addr)) {
			return null;
		}
		long string_size=get_address_value(get_address(string_struct_addr, value_size), value_size);
		return read_string(string_addr, (int)string_size);
	}

	String read_string_struct(long string_struct_addr_value, int value_size) {
		return read_string_struct(program.getAddressFactory().getAddress(String.format("%x", string_struct_addr_value)), value_size);
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

	Address get_gopclntab() {
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

			int tmp_quantum=(int)get_address_value(get_address(tmp_gopclntab_base, 6), 1);
			int tmp_pointer_size=(int)get_address_value(get_address(tmp_gopclntab_base, 7), 1);

			Address func_list_base=null;
			if(is_go116) {
				func_list_base=get_address(tmp_gopclntab_base, get_address_value(get_address(tmp_gopclntab_base, 8+tmp_pointer_size*6), tmp_pointer_size));
			}else {
				func_list_base=get_address(tmp_gopclntab_base, 8+tmp_pointer_size);
			}
			long func_addr_value=get_address_value(get_address(func_list_base, 0), tmp_pointer_size);
			long func_info_offset=get_address_value(get_address(func_list_base, tmp_pointer_size), tmp_pointer_size);
			long func_entry_value=0;
			if(is_go116) {
				func_entry_value=get_address_value(get_address(func_list_base, func_info_offset), tmp_pointer_size);
			}else {
				func_entry_value=get_address_value(get_address(tmp_gopclntab_base, func_info_offset), tmp_pointer_size);
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

	boolean init_gopclntab(Address addr) {
		if(gopclntab_base!=null) {
			return true;
		}
		if(addr==null) {
			addr=get_gopclntab();
		}
		this.gopclntab_base=addr;
		if(this.gopclntab_base==null) {
			append_message("Failed to get gopclntab");
			return false;
		}

		this.magic=(int)get_address_value(gopclntab_base, 4);                                // magic
		                                                                                     // two zero bytes
		this.quantum=(int)get_address_value(get_address(gopclntab_base, 6), 1);              // arch(x86=1, ?=2, arm=4)
		this.pointer_size=(int)get_address_value(get_address(gopclntab_base, 7), 1);         // pointer size
		if((quantum!=1 && quantum!=2 && quantum!=4) ||
				(pointer_size!=4 && pointer_size!=8)) {
			append_message(String.format("Invalid gopclntab addr: %x", gopclntab_base.getOffset()));
			this.gopclntab_base=null;
			return false;
		}

		return true;
	}

	boolean init_gopclntab() {
		return init_gopclntab(get_gopclntab());
	}

	boolean init_go_version()
	{
		if(go_version.length()>0) {
			return true;
		}
		// cmd/go/internal/version/version.go
		// "\xff Go buildinf:"
		byte build_info_magic[]= {(byte)0xff,(byte)0x20,(byte)0x47,(byte)0x6f,(byte)0x20,(byte)0x62,(byte)0x75,(byte)0x69,(byte)0x6c,(byte)0x64,(byte)0x69,(byte)0x6e,(byte)0x66,(byte)0x3a};
		Address base_addr=null;
		base_addr=memory.findBytes(base_addr, build_info_magic, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff}, true, monitor);
		if(base_addr==null) {
			append_message("Failed to find \"\\xff Go buildinf:\"");
			go_version="go0.0.0";
			return false;
		}

		byte size=(byte)get_address_value(get_address(base_addr, 14), 1);
		boolean is_big_endian=get_address_value(get_address(base_addr, 15), 1)!=0;
		if(is_big_endian) {
			append_message("Go version is big endian");
			return false;
		}

		go_version=read_string_struct(get_address_value(get_address(base_addr, 16), size), size);
		if(go_version=="")
		{
			return false;
		}

		go_version_mod=read_string_struct(get_address_value(get_address(base_addr, 16+size), size), size);
		if(go_version_mod.length()>=33 && go_version_mod.charAt(go_version_mod.length()-17)=='\n')
		{
			go_version_mod=go_version_mod.substring(16, go_version_mod.length()-16);
		}
		else {
			go_version_mod="";
		}
		return true;
	}

	int compare_go_version(String cmp_go_version) {
		init_go_version();
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
