package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;


public class InterfaceGolangDatatype extends GolangDatatype {
	private String pkg_name;
	private List<String> method_name_list;
	private List<Long> method_type_key_list;

	InterfaceGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	@Override
	public void make_datatype(DatatypeHolder datatype_searcher) {
		// runtime/iface.go
		StructureDataType interface_datatype=new StructureDataType(name, 0);
		interface_datatype.setPackingEnabled(true);
		interface_datatype.setExplicitMinimumAlignment(go_bin.get_pointer_size());
		interface_datatype.add(new PointerDataType(datatype_searcher.get_datatype_by_name("runtime._type"), go_bin.get_pointer_size()), "tab", "");
		interface_datatype.add(new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()), "data", "");
		datatype=interface_datatype;
	}

	public String get_pkg_name() {
		return pkg_name;
	}

	public List<String> get_method_name_list(){
		return method_name_list;
	}

	@Override
	void parse_datatype() {
		int pointer_size=go_bin.get_pointer_size();

		long pkg_path_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		long methods_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
		long methods_len=go_bin.get_address_value(ext_base_addr, pointer_size*2, pointer_size);

		pkg_name="";
		if(pkg_path_addr_value!=0) {
			pkg_name=get_type_string(go_bin.get_address(type_base_addr, pkg_path_addr_value-type_base_addr.getOffset()), 0);
		}
		method_name_list = new ArrayList<String>();
		method_type_key_list = new ArrayList<Long>();
		for(int i=0;i<methods_len;i++) {
			long method_name_offset=go_bin.get_address_value(type_base_addr, methods_addr_value+i*2*4-type_base_addr.getOffset(), 4);
			long method_type_offset=go_bin.get_address_value(type_base_addr, methods_addr_value+i*2*4-type_base_addr.getOffset()+4, 4);

			String method_name="";
			if(method_name_offset>0) {
				method_name=get_type_string(go_bin.get_address(type_base_addr, method_name_offset), 0);
			}
			if(method_type_offset>0)
			{
				dependence_type_key_list.add(method_type_offset);
			}
			method_name_list.add(method_name);
			method_type_key_list.add(method_type_offset);
		}

		if(check_tflag(tflag, Tflag.Uncommon)) {
			uncommon_base_addr=go_bin.get_address(ext_base_addr, pointer_size*4);
		}
	}
}
