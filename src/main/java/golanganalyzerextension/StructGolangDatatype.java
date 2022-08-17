package golanganalyzerextension;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;


class StructField {
	String name;
	long type_key;
	int offset;

	StructField(String name, long type_key, int offset){
		this.name=name;
		this.type_key=type_key;
		this.offset=offset;
	}
}

class StructGolangDatatype extends GolangDatatype {
	String pkg_name="";
	List<StructField> field_list=null;

	StructGolangDatatype(GolangDatatype basic_info, String pkg_name, List<StructField> field_list) {
		super(basic_info);
		this.pkg_name=pkg_name;
		this.field_list=field_list;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		StructureDataType structure_datatype=new StructureDataType(name, (int)size);
		structure_datatype.setPackingEnabled(true);
		structure_datatype.setExplicitMinimumAlignment(field_align);
		for(StructField field : field_list) {
			DataType field_datatype=new PointerDataType(new VoidDataType(), go_bin.get_pointer_size());
			if(datatype_map.containsKey(field.type_key)) {
				field_datatype=datatype_map.get(field.type_key).get_datatype(datatype_map);
			}
			if(field_datatype.getLength()>0){
				structure_datatype.insertAtOffset(field.offset, field_datatype, field_datatype.getLength(), field.name, null);
			}
		}
		return structure_datatype;
	}
}
