package golanganalyzerextension.string;

import ghidra.program.model.address.Address;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;

public class GolangString {

	private boolean is_struct;
	private Address addr;
	private String str;

	public GolangString(boolean is_struct, Address addr, String str) {
		this.is_struct=is_struct;
		this.addr=addr;
		this.str=str;
	}

	public static GolangString create_string(GolangBinary go_bin, Address addr, int str_len) throws InvalidBinaryStructureException {
		String str;
		try {
			str = go_bin.read_string(addr, str_len);
		} catch (BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Read string: addr=%x, str_len=%d", addr.getOffset(), str_len));
		}
		if(str.length()!=str_len) {
			throw new InvalidBinaryStructureException(String.format("Mismatched length: addr=%x, len=%d, str_len=%d", addr.getOffset(), str.length(), str_len));
		}
		return new GolangString(false, addr, str);
	}

	public static GolangString create_string_struct(GolangBinary go_bin, Address addr) throws InvalidBinaryStructureException {
		int pointer_size=go_bin.get_pointer_size();

		String str;
		try {
			long str_addr_value=go_bin.get_address_value(addr, pointer_size);
			if(!go_bin.is_valid_address(str_addr_value)) {
				throw new InvalidBinaryStructureException(String.format("Invalid string address: addr=%x", str_addr_value));
			}
			long str_len=go_bin.get_address_value(addr, pointer_size, pointer_size);
			if(str_len<=0 || str_len>=0x1000) {
				throw new InvalidBinaryStructureException(String.format("Invalid string length: str_len=%d", str_len));
			}
			if(go_bin.is_valid_address(addr.getOffset()+pointer_size*2)) {
				long str_len2=go_bin.get_address_value(addr, pointer_size*2, pointer_size);
				if(str_len==str_len2) {
					throw new InvalidBinaryStructureException(String.format("Length not match: str_len=%d, str_len=%d", str_len, str_len2));
				}
			}
			str=go_bin.read_string(go_bin.get_address(str_addr_value), (int)str_len);
			if(str.length()!=str_len) {
				throw new InvalidBinaryStructureException(String.format("Read string: addr=%x str_len=%d", str_addr_value, str_len));
			}
		} catch (BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Read string struct: addr=%s, message=%s", addr, e.getMessage()));
		}

		return new GolangString(true, addr, str);
	}

	public boolean get_is_struct() {
		return is_struct;
	}

	public Address get_addr() {
		return addr;
	}

	public String get_str() {
		return str;
	}
}
