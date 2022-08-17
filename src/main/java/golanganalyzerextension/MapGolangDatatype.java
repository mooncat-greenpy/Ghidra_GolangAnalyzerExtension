package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;


class MapGolangDatatype extends GolangDatatype {
	long key_type_key=0;
	long elem_type_key=0;

	MapGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16, boolean fix_label) {
		super(go_bin, type_base_addr, offset, is_go16, fix_label);
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		DataType map_datatype=new PointerDataType(get_datatype(datatype_map, true), go_bin.get_pointer_size());
		return map_datatype;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map, boolean once) {
		String struct_name=name;
		if(struct_name.length()>0 && struct_name.endsWith("*")) {
			struct_name=struct_name.substring(0, struct_name.length()-1);
		}

		// runtime/map.go
		StructureDataType hmap_datatype=new StructureDataType(struct_name, 0);
		hmap_datatype.setPackingEnabled(true);
		hmap_datatype.setExplicitMinimumAlignment(pointer_size);
		hmap_datatype.add(get_datatype_by_name("int", datatype_map), "count", "");
		hmap_datatype.add(get_datatype_by_name("uint8", datatype_map), "flags", "");
		hmap_datatype.add(get_datatype_by_name("uint8", datatype_map), "B", "");
		hmap_datatype.add(get_datatype_by_name("uint16", datatype_map), "noverflow", "");
		hmap_datatype.add(get_datatype_by_name("uint32", datatype_map), "hash0", "");
		hmap_datatype.add(get_datatype_by_name("unsafe.Pointer", datatype_map), "buckets", "");
		hmap_datatype.add(get_datatype_by_name("unsafe.Pointer", datatype_map), "oldbuckets", "");
		hmap_datatype.add(get_datatype_by_name("uintptr", datatype_map), "nevacuate", "");
		hmap_datatype.add(new PointerDataType(new VoidDataType(), pointer_size), "extra", "");
		return hmap_datatype;
	}

	@Override
	protected void parse_datatype() {
		long key_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		key_type_key=key_addr_value-type_base_addr.getOffset();
		long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
		elem_type_key=elem_addr_value-type_base_addr.getOffset();
		// ...
		if(key_type_key>0) {
			dependence_type_key_list.add(key_type_key);
		}
		if(elem_type_key>0) {
			dependence_type_key_list.add(elem_type_key);
		}
    }
}
