package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;


class PtrGolangDatatype extends GolangDatatype {
	long elem_type_key=0;

	PtrGolangDatatype(GolangDatatype basic_info, long elem_type_key) {
		super(basic_info);
		this.elem_type_key=elem_type_key;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		return new PointerDataType(new VoidDataType(), go_bin.get_pointer_size());
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map, boolean once) {
		if(!once) {
			return new PointerDataType(new VoidDataType(), go_bin.get_pointer_size());
		}
		DataType inner_datatype=null;
		if(datatype_map.containsKey(elem_type_key)) {
			inner_datatype=datatype_map.get(elem_type_key).get_datatype(datatype_map);
		}
		if(inner_datatype==null || inner_datatype.getLength()<=0) {
			inner_datatype=new VoidDataType();
		}
		DataType ptr_datatype=new PointerDataType(inner_datatype, go_bin.get_pointer_size());
		return ptr_datatype;
	}
}
