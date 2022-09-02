package golanganalyzerextension;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;


class SliceGolangDatatype extends GolangDatatype {
	long elem_type_key=0;

	SliceGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	@Override
	public DataType get_datatype(DatatypeSearcher datatype_searcher) {
		return get_datatype(datatype_searcher, false);
	}

	@Override
	public DataType get_datatype(DatatypeSearcher datatype_searcher, boolean once) {
		DataType inner_datatype=null;
		if(once) {
			inner_datatype=datatype_searcher.get_datatype_by_key(elem_type_key);
		}
		if(inner_datatype==null) {
			inner_datatype=new VoidDataType();
		}

		// cmd/cgo/out.go
		StructureDataType slice_datatype=new StructureDataType(name, 0);
		slice_datatype.setPackingEnabled(true);
		slice_datatype.setExplicitMinimumAlignment(pointer_size);
		slice_datatype.add(new PointerDataType(inner_datatype, pointer_size), "__values", null);
		slice_datatype.add(datatype_searcher.get_datatype_by_name("uintptr"), "__count", null);
		slice_datatype.add(datatype_searcher.get_datatype_by_name("uintptr"), "__capacity", null);
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
