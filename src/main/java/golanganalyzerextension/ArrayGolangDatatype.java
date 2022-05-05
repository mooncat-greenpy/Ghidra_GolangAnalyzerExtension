package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.VoidDataType;


class ArrayGolangDatatype extends GolangDatatype {
	long elem_type_key=0;
	long slice=0;
	int len=0;

	ArrayGolangDatatype(GolangDatatype basic_info, long elem_type_key, long slice, long len) {
		super(basic_info);
		this.elem_type_key=elem_type_key;
		this.slice=slice;
		this.len=(int)len;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		return get_datatype(datatype_map, false);
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map, boolean once) {
		if(len<=0) {
			return new VoidDataType();
		}
		DataType inner_datatype=null;
		if(once && datatype_map.containsKey(elem_type_key)) {
			inner_datatype=datatype_map.get(elem_type_key).get_datatype(datatype_map);
		}
		if(inner_datatype==null || inner_datatype.getLength()<=0) {
			inner_datatype=new UnsignedCharDataType();
		}
		ArrayDataType array_datatype=new ArrayDataType(inner_datatype, len, inner_datatype.getLength());
		return array_datatype;
	}
}
