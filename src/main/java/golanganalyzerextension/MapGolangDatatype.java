package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;


class MapGolangDatatype extends GolangDatatype {
	long key_type_key=0;
	long elem_type_key=0;

	MapGolangDatatype(GolangDatatype basic_info, long key_type_key, long elem_type_key) {
		super(basic_info);
		this.key_type_key=key_type_key;
		this.elem_type_key=elem_type_key;
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
		int pointer_size=go_bin.get_pointer_size();
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
}
