package golanganalyzerextension;

import ghidra.program.model.address.Address;

public class UncommonType {
	GolangBinary go_bin;

	String pkg_path;

	public UncommonType(GolangBinary go_bin, Address base_addr, Address type_base_addr, boolean is_go16) {
		this.go_bin=go_bin;

		long pkg_path_offset=go_bin.get_address_value(base_addr, 0, 4);
		pkg_path=get_type_string(type_base_addr.add(pkg_path_offset));			
	}

	private String get_type_string(Address address) {
		boolean is_go117=false;
		if(go_bin.compare_go_version("go1.17beta1")<=0) {
			is_go117=true;
		}

		String str=null;
		if(is_go117) {
			int str_size=(int)(go_bin.get_address_value(address, 1, 1));
			str=go_bin.read_string(go_bin.get_address(address, 2), str_size);
		}else {
			int str_size=(int)(go_bin.get_address_value(address, 1, 1)<<8)+(int)(go_bin.get_address_value(address, 2, 1));
			str=go_bin.read_string(go_bin.get_address(address, 3), str_size);
		}
		return str;
	}

	public String get_pkg_path() {
		return pkg_path;
	}
}
