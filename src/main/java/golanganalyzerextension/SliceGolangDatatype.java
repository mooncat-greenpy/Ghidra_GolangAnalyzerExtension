package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;


class SliceGolangDatatype extends GolangDatatype {
	long elem_type_key=0;

	SliceGolangDatatype(GolangDatatype basic_info, long elem_type_key) {
		super(basic_info);
		this.elem_type_key=elem_type_key;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		return get_datatype(datatype_map, false);
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map, boolean once) {
		DataType inner_datatype=null;
		if(once && datatype_map.containsKey(elem_type_key)) {
			inner_datatype=datatype_map.get(elem_type_key).get_datatype(datatype_map);
		}
		if(inner_datatype==null || inner_datatype.getLength()<=0) {
			inner_datatype=new VoidDataType();
		}
		int pointer_size=go_bin.get_pointer_size();
		// cmd/cgo/out.go
		StructureDataType slice_datatype=new StructureDataType(name, 0);
		slice_datatype.setPackingEnabled(true);
		slice_datatype.setExplicitMinimumAlignment(pointer_size);
		slice_datatype.add(new PointerDataType(inner_datatype, pointer_size), "__values", null);
		slice_datatype.add(get_datatype_by_name("uintptr", datatype_map), "__count", null);
		slice_datatype.add(get_datatype_by_name("uintptr", datatype_map), "__capacity", null);
		return slice_datatype;
	}
}
