package golanganalyzerextension;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;


class StructGolangDatatype extends GolangDatatype {
	String pkg_name="";
	List<String> field_name_list=null;
	List<Long> field_type_key_list=null;

	StructGolangDatatype(GolangDatatype basic_info, String pkg_name, List<String> field_name_list, List<Long> field_type_key_list) {
		super(basic_info);
		this.pkg_name=pkg_name;
		this.field_name_list=field_name_list;
		this.field_type_key_list=field_type_key_list;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		StructureDataType structure_datatype=new StructureDataType(name, (int)size);
		structure_datatype.setPackingEnabled(true);
		structure_datatype.setExplicitMinimumAlignment(field_align);
		for(int i=0;i<field_name_list.size();i++) {
			long field_key=field_type_key_list.get(i);
			DataType field_datatype=new PointerDataType(new VoidDataType(), go_bin.get_pointer_size());
			if(datatype_map.containsKey(field_key)) {
				field_datatype=datatype_map.get(field_key).get_datatype(datatype_map);
			}
			if(field_datatype.getLength()>0){
				structure_datatype.add(field_datatype, field_name_list.get(i), null);
			}
		}
		return structure_datatype;
	}
}
