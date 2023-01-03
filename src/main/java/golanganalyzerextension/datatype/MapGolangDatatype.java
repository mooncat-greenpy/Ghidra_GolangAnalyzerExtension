package golanganalyzerextension.datatype;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import golanganalyzerextension.DatatypeHolder;
import golanganalyzerextension.gobinary.GolangBinary;


public class MapGolangDatatype extends GolangDatatype {
	private long key_type_key;
	private long elem_type_key;

	MapGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	@Override
	public DataType get_inner_datatype(boolean once) {
		return new PointerDataType(datatype, go_bin.get_pointer_size());
	}

	@Override
	public void make_datatype(DatatypeHolder datatype_searcher) {
		String struct_name=name;
		if(struct_name.length()>0 && struct_name.endsWith("*")) {
			struct_name=struct_name.substring(0, struct_name.length()-1);
		}

		int pointer_size=go_bin.get_pointer_size();

		// runtime/map.go
		StructureDataType hmap_datatype=new StructureDataType(struct_name, 0);
		hmap_datatype.setPackingEnabled(true);
		hmap_datatype.setExplicitMinimumAlignment(pointer_size);
		hmap_datatype.add(datatype_searcher.get_datatype_by_name("int"), "count", "");
		hmap_datatype.add(datatype_searcher.get_datatype_by_name("uint8"), "flags", "");
		hmap_datatype.add(datatype_searcher.get_datatype_by_name("uint8"), "B", "");
		hmap_datatype.add(datatype_searcher.get_datatype_by_name("uint16"), "noverflow", "");
		hmap_datatype.add(datatype_searcher.get_datatype_by_name("uint32"), "hash0", "");
		hmap_datatype.add(datatype_searcher.get_datatype_by_name("unsafe.Pointer"), "buckets", "");
		hmap_datatype.add(datatype_searcher.get_datatype_by_name("unsafe.Pointer"), "oldbuckets", "");
		hmap_datatype.add(datatype_searcher.get_datatype_by_name("uintptr"), "nevacuate", "");
		hmap_datatype.add(new PointerDataType(new VoidDataType(), pointer_size), "extra", "");
		datatype=hmap_datatype;
	}

	@Override
	void parse_datatype() {
		int pointer_size=go_bin.get_pointer_size();

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

		if(check_tflag(tflag, Tflag.Uncommon)) {
			uncommon_base_addr=go_bin.get_address(ext_base_addr, pointer_size*4+1*2+2+4);
		}
    }
}
