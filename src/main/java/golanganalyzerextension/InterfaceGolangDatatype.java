package golanganalyzerextension;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;


class InterfaceGolangDatatype extends GolangDatatype {
	String pkg_name="";
	List<String> methods_name_list=null;
	List<Long> methods_type_key_list=null;

	InterfaceGolangDatatype(GolangDatatype basic_info, String pkg_name, List<String> methods_name_list, List<Long> methods_type_key_list) {
		super(basic_info);
		this.pkg_name=pkg_name;
		this.methods_name_list=methods_name_list;
		this.methods_type_key_list=methods_type_key_list;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		// runtime/iface.go
		StructureDataType interface_datatype=new StructureDataType(name, 0);
		interface_datatype.setPackingEnabled(true);
		interface_datatype.setExplicitMinimumAlignment(go_bin.get_pointer_size());
		interface_datatype.add(new PointerDataType(get_datatype_by_name("runtime._type", datatype_map), go_bin.get_pointer_size()), "tab", "");
		interface_datatype.add(new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()), "data", "");
		return interface_datatype;
	}
}
