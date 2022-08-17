package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;


class SliceGolangDatatype extends GolangDatatype {
	long elem_type_key=0;

	SliceGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16, boolean fix_label) {
		super(go_bin, type_base_addr, offset, is_go16, fix_label);
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

		// cmd/cgo/out.go
		StructureDataType slice_datatype=new StructureDataType(name, 0);
		slice_datatype.setPackingEnabled(true);
		slice_datatype.setExplicitMinimumAlignment(pointer_size);
		slice_datatype.add(new PointerDataType(inner_datatype, pointer_size), "__values", null);
		slice_datatype.add(get_datatype_by_name("uintptr", datatype_map), "__count", null);
		slice_datatype.add(get_datatype_by_name("uintptr", datatype_map), "__capacity", null);
		return slice_datatype;
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
