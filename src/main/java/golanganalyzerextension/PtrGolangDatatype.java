package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;


class PtrGolangDatatype extends GolangDatatype {
	long elem_type_key=0;

	PtrGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16, boolean fix_label) {
		super(go_bin, type_base_addr, offset, is_go16, fix_label);
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

	@Override
	protected void parse_datatype() {
		long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		elem_type_key=elem_addr_value-type_base_addr.getOffset();
		if(elem_type_key>0) {
			dependence_type_key_list.add(elem_type_key);
		}
	}
}
