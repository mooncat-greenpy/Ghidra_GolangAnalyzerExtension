package golanganalyzerextension.version;

import java.util.Optional;

import ghidra.program.model.address.Address;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;

class GolangBuildInfo {
	private GolangBinary go_bin;

	private String go_version;
	private Optional<String> module_version_opt;

	GolangBuildInfo(GolangBinary go_bin) throws InvalidBinaryStructureException {
		this.go_bin=go_bin;

		Address build_info_addr=get_build_info_addr();
		if(build_info_addr==null) {
			throw new InvalidBinaryStructureException("Not found \"\\xff Go buildinf:\"");
		} else {
			scan_build_info(build_info_addr);
		}
	}

	private Address get_build_info_addr() {
		// ver > go1.12.*
		// cmd/go/internal/version/version.go
		// "\xff Go buildinf:"
		byte build_info_magic[]={(byte)0xff,(byte)0x20,(byte)0x47,(byte)0x6f,(byte)0x20,(byte)0x62,(byte)0x75,(byte)0x69,(byte)0x6c,(byte)0x64,(byte)0x69,(byte)0x6e,(byte)0x66,(byte)0x3a};
		byte magic_mask[]={(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
		return go_bin.find_memory(null, build_info_magic, magic_mask).orElse(null);
	}

	private void scan_build_info(Address base_addr) {
		try {
			go_version=find_go_version(base_addr);
		} catch (BinaryAccessException | InvalidBinaryStructureException e) {
			throw new InvalidBinaryStructureException(String.format("Read go version: addr=%s, message=%s", base_addr, e.getMessage()));
		}
		try {
			module_version_opt=find_module_version(base_addr);
		} catch (BinaryAccessException | InvalidBinaryStructureException e) {
			module_version_opt=Optional.empty();
		}
	}

	String get_go_version() {
		return go_version;
	}

	Optional<String> get_module_version() {
		return module_version_opt;
	}

	String find_go_version(Address base_addr) throws BinaryAccessException {
		byte size=(byte)go_bin.get_address_value(base_addr, 14, 1);
		byte endian=(byte)go_bin.get_address_value(base_addr, 15, 1);
		if((endian&2)!=0) {
			byte str_size=(byte)go_bin.get_address_value(base_addr, 32, 1);
			return go_bin.read_string(go_bin.get_address(base_addr, 33), str_size);
		}

		return go_bin.read_string_struct(go_bin.get_address_value(base_addr, 16, size), size);
	}

	Optional<String> find_module_version(Address base_addr) throws BinaryAccessException {
		byte size=(byte)go_bin.get_address_value(base_addr, 14, 1);
		byte endian=(byte)go_bin.get_address_value(base_addr, 15, 1);

		Address bytes_addr;
		long bytes_size;
		if((endian&2)==0) {
			long addr_value=go_bin.get_address_value(base_addr, 16+size, size);
			if(!go_bin.is_valid_address(addr_value)) {
				return Optional.empty();
			}
			bytes_addr=go_bin.get_address(go_bin.get_address_value(addr_value, size));
			if(!go_bin.is_valid_address(bytes_addr)) {
				return Optional.empty();
			}
			bytes_size=go_bin.get_address_value(addr_value + size, size);
		} else {
			long ver_str_size=go_bin.get_address_value(base_addr, 32, 1);
			Address go_ver_end_addr=go_bin.get_address(base_addr, 32+1+ver_str_size);
			bytes_addr=go_bin.get_address(go_ver_end_addr, 1);
			bytes_size=go_bin.get_address_value(go_ver_end_addr, 1);
		}

		// runtime/debug/mod.go
		Address mod_bytes_addr=go_bin.get_address(bytes_addr, 16);
		Address mod_bytes_end=go_bin.get_address(bytes_addr, bytes_size-17);
		if(mod_bytes_addr==null || mod_bytes_end==null || go_bin.get_address_value(mod_bytes_end, 1)!='\n') {
			return Optional.empty();
		}

		return Optional.ofNullable(go_bin.read_string(mod_bytes_addr, (int)bytes_size-16-16));
	}
}
