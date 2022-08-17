package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.VoidDataType;


class ArrayGolangDatatype extends GolangDatatype {
	long elem_type_key=0;
	long slice=0;
	int len=0;

	ArrayGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16, boolean fix_label) {
		super(go_bin, type_base_addr, offset, is_go16, fix_label);
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

	@Override
	protected void parse_datatype() {
		long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		elem_type_key=elem_addr_value-type_base_addr.getOffset();
		slice=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
		len=(int)go_bin.get_address_value(ext_base_addr, pointer_size*2, pointer_size);

		dependence_type_key_list.add(elem_type_key);
	}
}
