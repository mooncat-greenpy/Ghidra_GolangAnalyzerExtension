package golanganalyzerextension;

import java.util.Optional;

import ghidra.program.model.address.Address;

public class GolangBuildInfo {
	private static final String DEFAULT_GO_VERSION="go0.0.0";

	private GolangBinary go_bin;

	private String go_version;
	private String module_version;

	public GolangBuildInfo(GolangBinary go_bin) {
		this.go_bin=go_bin;

		Optional<Address> build_info_addr=get_build_info_addr();
		build_info_addr.ifPresentOrElse(
			addr -> scan_build_info(addr),
			() -> {
				go_version=DEFAULT_GO_VERSION;
				module_version="";
				Logger.append_message("Failed to find \"\\xff Go buildinf:\"");
			}
		);
	}

	private Optional<Address> get_build_info_addr() {
		// cmd/go/internal/version/version.go
		// "\xff Go buildinf:"
		byte build_info_magic[]={(byte)0xff,(byte)0x20,(byte)0x47,(byte)0x6f,(byte)0x20,(byte)0x62,(byte)0x75,(byte)0x69,(byte)0x6c,(byte)0x64,(byte)0x69,(byte)0x6e,(byte)0x66,(byte)0x3a};
		byte magic_mask[]={(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
		return Optional.ofNullable(go_bin.find_memory(null, build_info_magic, magic_mask));
	}

	private void scan_build_info(Address base_addr) {
		Optional<String> go_version_opt=find_go_version(base_addr);
		go_version_opt.ifPresentOrElse(
				s -> {if (is_go_version(s)) {go_version=s;} else {go_version=DEFAULT_GO_VERSION;}},
				() -> go_version=DEFAULT_GO_VERSION
			);
		Optional<String> module_version_opt=find_module_version(base_addr);
		module_version_opt.ifPresentOrElse(s -> module_version=s, () -> module_version="");
	}

	public boolean is_go_version(String str) {
		return str.matches("go\\d+(\\.\\d*(beta\\d*|rc\\d*|(\\.\\d+)?))?");
	}

	public String get_go_version() {
		return go_version;
	}

	public String get_module_version() {
		return module_version;
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

	public int compare_go_version(String cmp_go_version) {
		return compare_go_version(cmp_go_version, go_version.length()>2?go_version:DEFAULT_GO_VERSION);
	}

	public int compare_go_version(String cmp_go_version1, String cmp_go_version2) {
		String cmp1=cmp_go_version1.substring(2);
		String cmp2=cmp_go_version2.substring(2);
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
