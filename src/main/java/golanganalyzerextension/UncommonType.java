package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import ghidra.program.model.address.Address;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;

public class UncommonType {
	private GolangBinary go_bin;

	private String pkg_path;
	private List<UncommonMethod> method_list;

	public UncommonType(GolangBinary go_bin, Address base_addr, Address type_base_addr, boolean is_go16) throws InvalidBinaryStructureException {
		this.go_bin=go_bin;

		if(is_go16) {
			long pkgpath_addr_value=go_bin.get_address_value(base_addr, go_bin.get_pointer_size(), go_bin.get_pointer_size());
			pkg_path=go_bin.read_string_struct(go_bin.get_address(pkgpath_addr_value), go_bin.get_pointer_size()).orElse(null);
		} else {
			long pkg_path_offset=go_bin.get_address_value(base_addr, 0, 4);
			pkg_path=get_type_string(type_base_addr.add(pkg_path_offset));
		}
		if(pkg_path==null) {
			 throw new InvalidBinaryStructureException("Failed to get UncommonType pkgpath");
		}

		method_list=new ArrayList<>();

		scan_methods(base_addr, type_base_addr, is_go16);
	}

	private String get_type_string(Address address) {
		boolean is_go117=false;
		if(go_bin.ge_go_version("go1.17beta1")) {
			is_go117=true;
		}

		String str=null;
		if(is_go117) {
			int str_size=(int)(go_bin.get_address_value(address, 1, 1));
			str=go_bin.read_string(go_bin.get_address(address, 2), str_size).orElse(null);
		}else {
			int str_size=(int)(go_bin.get_address_value(address, 1, 1)<<8)+(int)(go_bin.get_address_value(address, 2, 1));
			str=go_bin.read_string(go_bin.get_address(address, 3), str_size).orElse(null);
		}
		if(str==null) {
			throw new InvalidBinaryStructureException(String.format("Failed to get type string: addr=%x", address.getOffset()));
		}
		return str;
	}

	public String get_pkg_path() {
		return pkg_path;
	}

	public class UncommonMethod {
		private GolangBinary go_bin_inner;

		private String name;
		private long type_offset;
		private Address interface_method_addr;
		private Address normal_method_addr;

		UncommonMethod(GolangBinary go_bin, Address base_addr, Address type_base_addr, boolean is_go16) throws InvalidBinaryStructureException {
			this.go_bin_inner=go_bin;

			if(is_go16) {
				parse_go16(base_addr, type_base_addr);
			} else {
				parse_after_go16(base_addr, type_base_addr);
			}
		}

		private void parse_after_go16(Address base_addr, Address type_base_addr) {
			long name_offset=go_bin_inner.get_address_value(base_addr, 0, 4);
			long mtyp_offset=go_bin_inner.get_address_value(base_addr, 4, 4);
			long ifn_offset=go_bin_inner.get_address_value(base_addr, 4*2, 4);
			long tfn_offset=go_bin_inner.get_address_value(base_addr, 4*3, 4);

			this.name=get_type_string(type_base_addr.add(name_offset));
			if(mtyp_offset!=-1) {
				this.type_offset=mtyp_offset;
			} else {
				this.type_offset=0;
			}

			Optional<Address> text_base_addr_opt=go_bin_inner.get_text_base();
			this.interface_method_addr=go_bin_inner.get_address(0);
			text_base_addr_opt.ifPresent(addr -> {if(ifn_offset!=0 && ifn_offset!=-1) {this.interface_method_addr=addr.add(ifn_offset);}});
			this.normal_method_addr=go_bin_inner.get_address(0);
			text_base_addr_opt.ifPresent(addr -> {if(tfn_offset!=0 && tfn_offset!=-1) {this.normal_method_addr=addr.add(tfn_offset);}});
		}

		private void parse_go16(Address base_addr, Address type_base_addr) {
			int pointer_size=go_bin_inner.get_pointer_size();

			long name_addr_value=go_bin_inner.get_address_value(base_addr, 0, pointer_size);
			long mtyp_addr_value=go_bin_inner.get_address_value(base_addr, pointer_size*2, pointer_size);
			long ifn_addr_value=go_bin_inner.get_address_value(base_addr, pointer_size*4, pointer_size);
			long tfn_addr_value=go_bin_inner.get_address_value(base_addr, pointer_size*5, pointer_size);

			this.name=go_bin_inner.read_string_struct(name_addr_value, go_bin_inner.get_pointer_size()).orElse(null);
			if(this.name==null) {
				 throw new InvalidBinaryStructureException("Failed to get UncommonMethod name: version <= go1.6*");
			}
			this.type_offset=mtyp_addr_value-type_base_addr.getOffset();
			this.interface_method_addr=go_bin_inner.get_address(ifn_addr_value);
			this.normal_method_addr=go_bin_inner.get_address(tfn_addr_value);
		}

		public String get_name() {
			return name;
		}

		public long get_type_offset() {
			return type_offset;
		}

		public Address get_interface_method_addr() {
			return interface_method_addr;
		}

		public Address get_normal_method_addr() {
			return normal_method_addr;
		}
	}

	private void scan_methods(Address base_addr, Address type_base_addr, boolean is_go16) {
		if(is_go16) {
			scan_methods_go16(base_addr, type_base_addr);
		} else {			
			scan_methods_after_go16(base_addr, type_base_addr);
		}
	}

	private void scan_methods_after_go16(Address base_addr, Address type_base_addr) {
		long mcount=go_bin.get_address_value(base_addr, 4, 2);
		// xcount
		long moff=go_bin.get_address_value(base_addr, 4+2*2, 4);
		Address methods_base_addr=go_bin.get_address(base_addr, moff);
		for(int i=0; i<mcount; i++) {
			method_list.add(new UncommonMethod(
					go_bin,
					methods_base_addr.add(i*4*4),
					type_base_addr,
					false));
		}
	}

	private void scan_methods_go16(Address base_addr, Address type_base_addr) {
		int pointer_size=go_bin.get_pointer_size();
		long mhdr_addr_value=go_bin.get_address_value(base_addr, pointer_size*2, pointer_size);
		long mhdr_len=go_bin.get_address_value(base_addr, pointer_size*3, pointer_size);

		for(int i=0; i<mhdr_len; i++) {
			method_list.add(new UncommonMethod(
					go_bin,
					go_bin.get_address(mhdr_addr_value+i*pointer_size*6),
					type_base_addr,
					true));
		}
	}

	public List<UncommonMethod> get_method_list() {
		return method_list;
	}
}