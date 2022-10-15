package golanganalyzerextension;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import golanganalyzerextension.StructureManager.Tflag;


class PtrGolangDatatype extends GolangDatatype {
	long elem_type_key=0;

	PtrGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	@Override
	public StructureDataType get_datatype(DatatypeSearcher datatype_searcher) {
		StructureDataType ptr_datatype=new StructureDataType(name, 0);
		ptr_datatype.add(new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()));
		return ptr_datatype;
	}

	@Override
	public StructureDataType get_datatype(DatatypeSearcher datatype_searcher, boolean once) {
		StructureDataType ptr_datatype=new StructureDataType(name, 0);
		if(!once) {
			ptr_datatype.add(new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()));
			return ptr_datatype;
		}
		DataType inner_datatype=datatype_searcher.get_datatype_by_key(elem_type_key);
		if(inner_datatype==null) {
			inner_datatype=new VoidDataType();
		}
		ptr_datatype.add(new PointerDataType(inner_datatype, go_bin.get_pointer_size()));
		return ptr_datatype;
	}

	@Override
	protected void parse_datatype() {
		long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		elem_type_key=elem_addr_value-type_base_addr.getOffset();
		if(elem_type_key>0) {
			dependence_type_key_list.add(elem_type_key);
		}

		if(check_tflag(tflag, Tflag.Uncommon)) {
			uncommon_base_addr=go_bin.get_address(ext_base_addr, pointer_size);
		}
	}
}
