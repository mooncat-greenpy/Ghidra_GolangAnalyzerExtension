package golanganalyzerextension.gobinary;

import ghidra.program.model.address.Address;
import golanganalyzerextension.datatype.GolangDatatype;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;

public class ModuleData {

	private GolangBinary go_bin;
	private Address base_addr;

	private Address type_addr;
	private Address typelink_addr;
	private long typelink_len;
	private Address text_addr;
	private boolean is_go16;

	public ModuleData(GolangBinary go_bin, Address base_addr) throws InvalidBinaryStructureException {
		this.go_bin=go_bin;
		this.base_addr=base_addr;

		if(!parse()) {
			throw new InvalidBinaryStructureException("Parsing module data");
		}
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

	public boolean get_is_go16() {
		return is_go16;
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
		is_go16=false;

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
		is_go16=false;

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
		is_go16=false;

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
		is_go16=false;

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
		is_go16=false;

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

		if(!is_golang_type(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4), true)) {
			return false;
		}

		type_addr=tmp_type_addr;
		typelink_addr=tmp_typelink_addr;
		typelink_len=tmp_typelink_len;
		text_addr=tmp_text_addr;
		is_go16=true;

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
