package golanganalyzerextension.datatype;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import ghidra.program.model.address.Address;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;

public class UncommonType implements Serializable {

	private String pkg_path;
	private List<UncommonMethod> method_list;

	UncommonType(GolangBinary go_bin, Address base_addr, Address type_base_addr, boolean is_go16) throws InvalidBinaryStructureException {
		try {
			if(is_go16) {
				long pkgpath_addr_value=go_bin.get_address_value(base_addr, go_bin.get_pointer_size(), go_bin.get_pointer_size());
				this.pkg_path=go_bin.read_string_struct(go_bin.get_address(pkgpath_addr_value), go_bin.get_pointer_size());
			} else {
				long pkg_path_offset=go_bin.get_address_value(base_addr, 0, 4);
				Address pkg_path_addr=go_bin.get_address(type_base_addr, pkg_path_offset);
				this.pkg_path=get_type_string(go_bin, pkg_path_addr);
			}
		} catch (BinaryAccessException e) {
			 throw new InvalidBinaryStructureException(String.format("Get UncommonType pkgpath: type_addr=%s, addr=%s, go16=%b, message=%s", type_base_addr, base_addr, is_go16, e.getMessage()));
		}

		method_list=new ArrayList<>();

		scan_methods(go_bin, base_addr, type_base_addr, is_go16);
	}

	public String get_pkg_path() {
		return pkg_path;
	}

	public List<UncommonMethod> get_method_list() {
		return method_list;
	}

	private String get_type_string(GolangBinary go_bin, Address address) {
		boolean is_go117=false;
		if(go_bin.ge_go_version("go1.17beta1")) {
			is_go117=true;
		}

		try {
			String str;
			if(is_go117) {
				int str_size=(int)(go_bin.get_address_value(address, 1, 1));
				str=go_bin.read_string(go_bin.get_address(address, 2), str_size);
			}else {
				int str_size=(int)(go_bin.get_address_value(address, 1, 1)<<8)+(int)(go_bin.get_address_value(address, 2, 1));
				str=go_bin.read_string(go_bin.get_address(address, 3), str_size);
			}
			return str;
		} catch (BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Get type string: addr=%s, message=%s", address, e.getMessage()));
		}
	}

	public class UncommonMethod implements Serializable {

		private String name;
		private long type_offset;
		private Long interface_method_addr;
		private Long normal_method_addr;

		UncommonMethod(GolangBinary go_bin, Address base_addr, Address type_base_addr, boolean is_go16) throws InvalidBinaryStructureException {
			try {
				if(is_go16) {
					parse_go16(go_bin, base_addr, type_base_addr);
				} else {
					parse_after_go16(go_bin, base_addr, type_base_addr);
				}
			} catch (BinaryAccessException e) {
				throw new InvalidBinaryStructureException(String.format("UncommonMethod: type_addr=%s, addr=%s, go16=%b, message=%s", type_base_addr, base_addr, is_go16, e.getMessage()));
			}
		}

		private void parse_after_go16(GolangBinary go_bin, Address base_addr, Address type_base_addr) throws BinaryAccessException {
			long name_offset=go_bin.get_address_value(base_addr, 0, 4);
			long mtyp_offset=go_bin.get_address_value(base_addr, 4, 4);
			long ifn_offset=go_bin.get_address_value(base_addr, 4*2, 4);
			long tfn_offset=go_bin.get_address_value(base_addr, 4*3, 4);

			Address name_addr=go_bin.get_address(type_base_addr, name_offset);
			this.name=get_type_string(go_bin, name_addr);
			if(mtyp_offset!=-1) {
				this.type_offset=mtyp_offset;
			} else {
				this.type_offset=0;
			}

			Address text_base_addr=go_bin.get_text_base().orElse(null);
			this.interface_method_addr=null;
			this.normal_method_addr=null;
			if(text_base_addr==null) {
				return;
			}
			if(ifn_offset!=0 && ifn_offset!=-1) {
				this.interface_method_addr=go_bin.get_address(text_base_addr, ifn_offset).getOffset();
			}
			if(tfn_offset!=0 && tfn_offset!=-1) {
				this.normal_method_addr=go_bin.get_address(text_base_addr, tfn_offset).getOffset();
			}
		}

		private void parse_go16(GolangBinary go_bin, Address base_addr, Address type_base_addr) throws BinaryAccessException {
			int pointer_size=go_bin.get_pointer_size();

			long name_addr_value=go_bin.get_address_value(base_addr, 0, pointer_size);
			long mtyp_addr_value=go_bin.get_address_value(base_addr, pointer_size*2, pointer_size);
			long ifn_addr_value=go_bin.get_address_value(base_addr, pointer_size*4, pointer_size);
			long tfn_addr_value=go_bin.get_address_value(base_addr, pointer_size*5, pointer_size);

			this.name=go_bin.read_string_struct(name_addr_value, go_bin.get_pointer_size());

			this.type_offset=mtyp_addr_value-type_base_addr.getOffset();
			this.interface_method_addr=ifn_addr_value;
			this.normal_method_addr=tfn_addr_value;
		}

		public String get_name() {
			return name;
		}

		public long get_type_offset() {
			return type_offset;
		}

		public Optional<Long> get_interface_method_addr() {
			return Optional.ofNullable(interface_method_addr);
		}

		public Optional<Long> get_normal_method_addr() {
			return Optional.ofNullable(normal_method_addr);
		}
	}

	private void scan_methods(GolangBinary go_bin, Address base_addr, Address type_base_addr, boolean is_go16) {
		try {
			if(is_go16) {
				scan_methods_go16(go_bin, base_addr, type_base_addr);
			} else {
				scan_methods_after_go16(go_bin, base_addr, type_base_addr);
			}
		} catch (BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Scan uncommon methods: type_addr=%s, addr=%s, go16=%b", type_base_addr, base_addr, is_go16));
		}
	}

	private void scan_methods_after_go16(GolangBinary go_bin, Address base_addr, Address type_base_addr) throws BinaryAccessException {
		long mcount=go_bin.get_address_value(base_addr, 4, 2);
		// xcount
		long moff=go_bin.get_address_value(base_addr, 4+2*2, 4);
		Address methods_base_addr=go_bin.get_address(base_addr, moff);
		for(int i=0; i<mcount; i++) {
			Address method_base_addr=go_bin.get_address(methods_base_addr, i*4*4);
			method_list.add(new UncommonMethod(
					go_bin,
					method_base_addr,
					type_base_addr,
					false));
		}
	}

	private void scan_methods_go16(GolangBinary go_bin, Address base_addr, Address type_base_addr) throws BinaryAccessException {
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
}