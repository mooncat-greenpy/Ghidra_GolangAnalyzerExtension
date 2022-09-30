package golanganalyzerextension;

import java.util.Optional;

import ghidra.program.model.address.Address;

public class GolangBuildInfo {
	private GolangBinary go_bin;

	private Optional<String> go_version_opt;
	private Optional<String> module_version_opt;

	public GolangBuildInfo(GolangBinary go_bin) {
		this.go_bin=go_bin;

		Optional<Address> build_info_addr=get_build_info_addr();
		build_info_addr.ifPresentOrElse(
			addr -> scan_build_info(addr),
			() -> {
				go_version_opt=Optional.empty();
				module_version_opt=Optional.empty();
				Logger.append_message("Failed to find \"\\xff Go buildinf:\"");
			}
		);
	}

	private Optional<Address> get_build_info_addr() {
		// ver > go1.12.*
		// cmd/go/internal/version/version.go
		// "\xff Go buildinf:"
		byte build_info_magic[]={(byte)0xff,(byte)0x20,(byte)0x47,(byte)0x6f,(byte)0x20,(byte)0x62,(byte)0x75,(byte)0x69,(byte)0x6c,(byte)0x64,(byte)0x69,(byte)0x6e,(byte)0x66,(byte)0x3a};
		byte magic_mask[]={(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
		return Optional.ofNullable(go_bin.find_memory(null, build_info_magic, magic_mask));
	}

	private void scan_build_info(Address base_addr) {
		go_version_opt=find_go_version(base_addr);
		module_version_opt=find_module_version(base_addr);
	}

	public Optional<String> get_go_version() {
		return go_version_opt;
	}

	public Optional<String> get_module_version() {
		return module_version_opt;
	}

	public Optional<String> find_go_version(Address base_addr) {
		byte size=(byte)go_bin.get_address_value(base_addr, 14, 1);
		byte endian=(byte)go_bin.get_address_value(base_addr, 15, 1);
		if((endian&2)!=0) {
			byte str_size=(byte)go_bin.get_address_value(base_addr, 32, 1);
			return Optional.ofNullable(go_bin.read_string(go_bin.get_address(base_addr, 33), str_size));
		}
		boolean is_big_endian=endian!=0;
		if(is_big_endian) {
			Logger.append_message("Go version is big endian");
			return Optional.empty();
		}

		return Optional.ofNullable(go_bin.read_string_struct(go_bin.get_address_value(base_addr, 16, size), size));
	}

	public Optional<String> find_module_version(Address base_addr) {
		byte size=(byte)go_bin.get_address_value(base_addr, 14, 1);

		long addr_value=go_bin.get_address_value(base_addr, 16+size, size);
		if(!go_bin.is_valid_address(addr_value)) {
			return Optional.empty();
		}
		Address bytes_addr=go_bin.get_address(go_bin.get_address_value(addr_value, size));
		if(!go_bin.is_valid_address(bytes_addr)) {
			return Optional.empty();
		}
		long bytes_size=go_bin.get_address_value(addr_value + size, size);

		if(go_bin.get_address_value(bytes_addr.add(bytes_size-17), 1)!='\n') {
			return Optional.empty();
		}

		// runtime/debug/mod.go
		return Optional.ofNullable(go_bin.read_string(bytes_addr.add(16), (int)bytes_size-16-16));
	}
}
