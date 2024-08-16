package golanganalyzerextension.gobinary;

import ghidra.program.model.address.Address;
import golanganalyzerextension.datatype.GolangDatatype;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;
import golanganalyzerextension.version.GolangVersion;

public class ModuleData {

	private GolangBinary go_bin;
	private Address base_addr;

	private Address type_addr;
	private Address typelink_addr;
	private long typelink_len;
	private Address text_addr;
	private GolangVersion go_version;

	public ModuleData(GolangBinary go_bin) throws InvalidBinaryStructureException {
		this.go_bin=go_bin;

		if(!search_by_magic()) {
			throw new InvalidBinaryStructureException(String.format("Searching module data: addr=%s", base_addr));
		}
	}

	private boolean search_by_magic() {
		int pointer_size=go_bin.get_pointer_size();

		byte gopclntab_base_bytes[]=new byte[pointer_size];
		byte gopclntab_base_mask[]=new byte[pointer_size];
		long gopclntab_base_value=go_bin.get_pcheader_base().getOffset();
		if(go_bin.is_little_endian()) {
			for(int i=0; i<pointer_size; i++) {
				gopclntab_base_bytes[i]=(byte)(gopclntab_base_value&0xff);
				gopclntab_base_value>>=8;
				gopclntab_base_mask[i]=(byte)0xff;
			}
		} else {
			for(int i=pointer_size-1; i>=0; i--) {
				gopclntab_base_bytes[i]=(byte)(gopclntab_base_value&0xff);
				gopclntab_base_value>>=8;
				gopclntab_base_mask[i]=(byte)0xff;
			}
		}

		Address tmp_base_addr=null;
		while(true) {
			try {
				tmp_base_addr=go_bin.find_memory(tmp_base_addr, gopclntab_base_bytes, gopclntab_base_mask).orElse(null);

				if(tmp_base_addr==null) {
					break;
				}

				base_addr=tmp_base_addr;
				if (parse()) {
					return true;
				} else {
					Logger.append_message(String.format("Failed to parse module data: addr=%s", tmp_base_addr));
					tmp_base_addr=go_bin.get_address(tmp_base_addr, 4);
				}
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to get module data: addr=%s, message=%s", tmp_base_addr, e.getMessage()));
				break;
			}
		}
		return false;
	}

	private boolean parse() {
		boolean is_go120=false;
		boolean is_go118=false;
		boolean is_go116=false;
		boolean is_go18=false;
		boolean is_go17=false;
		if(go_bin.ge_go_version("go1.20beta1")) {
			is_go120=true;
		} else if(go_bin.ge_go_version("go1.18beta1")) {
			is_go118=true;
		} else if(go_bin.ge_go_version("go1.16beta1")) {
			is_go116=true;
		} else if(go_bin.ge_go_version("go1.8beta1")) {
			is_go18=true;
		} else if(go_bin.ge_go_version("go1.7beta1")) {
			is_go17=true;
		}

		// runtime/symtab.go
		boolean parsed=false;
		if(!parsed || is_go120) {
			try {
				parsed=parse_go120(base_addr);
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to parse moduledata: addr=%s, ver=go1.20", base_addr));
			}
		}
		if(!parsed || is_go118) {
			try {
				parsed=parse_go118(base_addr);
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to parse moduledata: addr=%s, ver=go1.18", base_addr));
			}
		}
		if(!parsed || is_go116) {
			try {
				parsed=parse_go116(base_addr);
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to parse moduledata: addr=%s, ver=go1.16", base_addr));
			}
		}
		if(!parsed || is_go18) {
			try {
				parsed=parse_go18(base_addr);
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to parse moduledata: addr=%s, ver=go1.8", base_addr));
			}
		}
		if(!parsed || is_go17) {
			try {
				parsed=parse_go17(base_addr);
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to parse moduledata: addr=%s, ver=go1.7", base_addr));
			}
		}
		if(!parsed) {
			try {
				parsed=parse(base_addr);
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to parse moduledata: addr=%s", base_addr));
			}
		}

		return parsed;
	}

	public Address get_base_addr() {
		return base_addr;
	}

	public Address get_type_addr() {
		return type_addr;
	}

	public Address get_typelink_addr() {
		return typelink_addr;
	}

	public long get_typelink_len() {
		return typelink_len;
	}

	public Address get_text_addr() {
		return text_addr;
	}

	public GolangVersion get_go_version() {
		return go_version;
	}

	public boolean get_is_go16() {
		return go_version.lt("go1.7beta1");
	}

	private boolean is_golang_type(Address type_base_addr, long offset, boolean is_go16) {
		try {
			GolangDatatype.create_by_parsing(go_bin, type_base_addr, offset, is_go16);
		} catch(InvalidBinaryStructureException e) {
			return false;
		}
		return true;
	}

	private boolean parse_go120(Address base_addr) throws BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

		long tmp_type_addr_value=go_bin.get_address_value(base_addr, 37*pointer_size, pointer_size);
		Address tmp_type_addr=go_bin.get_address(tmp_type_addr_value);
		long tmp_typelink_addr_value=go_bin.get_address_value(base_addr, 44*pointer_size, pointer_size);
		Address tmp_typelink_addr=go_bin.get_address(tmp_typelink_addr_value);
		long tmp_typelink_len=go_bin.get_address_value(base_addr, 45*pointer_size, pointer_size);
		Address tmp_text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 22*pointer_size, pointer_size));

		if(!check_type(tmp_type_addr) || !check_typelink(tmp_typelink_addr) || !check_text(tmp_text_addr)) {
			return false;
		}

		if(!is_golang_type(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4), false)) {
			return false;
		}

		type_addr=tmp_type_addr;
		typelink_addr=tmp_typelink_addr;
		typelink_len=tmp_typelink_len;
		text_addr=tmp_text_addr;
		go_version=new GolangVersion("go1.20beta1");

		return true;
	}

	private boolean parse_go118(Address base_addr) throws BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

		long tmp_type_addr_value=go_bin.get_address_value(base_addr, 35*pointer_size, pointer_size);
		Address tmp_type_addr=go_bin.get_address(tmp_type_addr_value);
		long tmp_typelink_addr_value=go_bin.get_address_value(base_addr, 42*pointer_size, pointer_size);
		Address tmp_typelink_addr=go_bin.get_address(tmp_typelink_addr_value);
		long tmp_typelink_len=go_bin.get_address_value(base_addr, 43*pointer_size, pointer_size);
		Address tmp_text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 22*pointer_size, pointer_size));

		if(!check_type(tmp_type_addr) || !check_typelink(tmp_typelink_addr) || !check_text(tmp_text_addr)) {
			return false;
		}

		if(!is_golang_type(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4), false)) {
			return false;
		}

		type_addr=tmp_type_addr;
		typelink_addr=tmp_typelink_addr;
		typelink_len=tmp_typelink_len;
		text_addr=tmp_text_addr;
		go_version=new GolangVersion("go1.18beta1");

		return true;
	}

	private boolean parse_go116(Address base_addr) throws BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

		long tmp_type_addr_value=go_bin.get_address_value(base_addr, 35*pointer_size, pointer_size);
		Address tmp_type_addr=go_bin.get_address(tmp_type_addr_value);
		long tmp_typelink_addr_value=go_bin.get_address_value(base_addr, 40*pointer_size, pointer_size);
		Address tmp_typelink_addr=go_bin.get_address(tmp_typelink_addr_value);
		long tmp_typelink_len=go_bin.get_address_value(base_addr, 41*pointer_size, pointer_size);
		Address tmp_text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 22*pointer_size, pointer_size));

		if(!check_type(tmp_type_addr) || !check_typelink(tmp_typelink_addr) || !check_text(tmp_text_addr)) {
			return false;
		}

		if(!is_golang_type(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4), false)) {
			return false;
		}

		type_addr=tmp_type_addr;
		typelink_addr=tmp_typelink_addr;
		typelink_len=tmp_typelink_len;
		text_addr=tmp_text_addr;
		go_version=new GolangVersion("go1.16beta1");

		return true;
	}

	private boolean parse_go18(Address base_addr) throws BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

		long tmp_type_addr_value=go_bin.get_address_value(base_addr, 25*pointer_size, pointer_size);
		Address tmp_type_addr=go_bin.get_address(tmp_type_addr_value);
		long tmp_typelink_addr_value=go_bin.get_address_value(base_addr, 30*pointer_size, pointer_size);
		Address tmp_typelink_addr=go_bin.get_address(tmp_typelink_addr_value);
		long tmp_typelink_len=go_bin.get_address_value(base_addr, 31*pointer_size, pointer_size);
		Address tmp_text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 12*pointer_size, pointer_size));

		if(!check_type(tmp_type_addr) || !check_typelink(tmp_typelink_addr) || !check_text(tmp_text_addr)) {
			return false;
		}

		if(!is_golang_type(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4), false)) {
			return false;
		}

		type_addr=tmp_type_addr;
		typelink_addr=tmp_typelink_addr;
		typelink_len=tmp_typelink_len;
		text_addr=tmp_text_addr;
		go_version=new GolangVersion("go1.8beta1");

		return true;
	}

	private boolean parse_go17(Address base_addr) throws BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

		long tmp_type_addr_value=go_bin.get_address_value(base_addr, 25*pointer_size, pointer_size);
		Address tmp_type_addr=go_bin.get_address(tmp_type_addr_value);
		long tmp_typelink_addr_value=go_bin.get_address_value(base_addr, 27*pointer_size, pointer_size);
		Address tmp_typelink_addr=go_bin.get_address(tmp_typelink_addr_value);
		long tmp_typelink_len=go_bin.get_address_value(base_addr, 28*pointer_size, pointer_size);
		Address tmp_text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 12*pointer_size, pointer_size));

		if(!check_type(tmp_type_addr) || !check_typelink(tmp_typelink_addr) || !check_text(tmp_text_addr)) {
			return false;
		}

		if(!is_golang_type(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4), false)) {
			return false;
		}

		type_addr=tmp_type_addr;
		typelink_addr=tmp_typelink_addr;
		typelink_len=tmp_typelink_len;
		text_addr=tmp_text_addr;
		go_version=new GolangVersion("go1.7beta1");

		return true;
	}

	private boolean parse(Address base_addr) throws BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

		long tmp_type_addr_value=0;
		Address tmp_type_addr=go_bin.get_address(tmp_type_addr_value);
		long tmp_typelink_addr_value=go_bin.get_address_value(base_addr, 25*pointer_size, pointer_size);
		Address tmp_typelink_addr=go_bin.get_address(tmp_typelink_addr_value);
		long tmp_typelink_len=go_bin.get_address_value(base_addr, 26*pointer_size, pointer_size);
		Address tmp_text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 12*pointer_size, pointer_size));

		if(!check_typelink(tmp_typelink_addr) || !check_text(tmp_text_addr)) {
			return false;
		}

		if(!is_golang_type(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, pointer_size), true)) {
			return false;
		}

		type_addr=tmp_type_addr;
		typelink_addr=tmp_typelink_addr;
		typelink_len=tmp_typelink_len;
		text_addr=tmp_text_addr;
		go_version=new GolangVersion("go1.6beta1");

		return true;
	}

	private boolean check_type(Address addr) {
		if(go_bin.is_valid_address(addr))
		{
			return true;
		}
		return false;
	}

	private boolean check_typelink(Address addr) {
		if(go_bin.is_valid_address(addr))
		{
			return true;
		}
		return false;
	}

	private boolean check_text(Address addr) {
		if(go_bin.is_valid_address(addr))
		{
			return true;
		}
		return false;
	}
}
