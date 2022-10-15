package golanganalyzerextension;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import golanganalyzerextension.StructureManager.Tflag;


class ArrayGolangDatatype extends GolangDatatype {
	long elem_type_key=0;
	long slice=0;
	int len=0;

	ArrayGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	@Override
	public StructureDataType get_datatype(DatatypeSearcher datatype_searcher) {
		return get_datatype(datatype_searcher, false);
	}

	@Override
	public StructureDataType get_datatype(DatatypeSearcher datatype_searcher, boolean once) {
		StructureDataType array_datatype=new StructureDataType(name, 0);
		if(len<=0) {
			array_datatype.add(new VoidDataType());
			return array_datatype;
		}
		DataType inner_datatype=null;
		if(once) {
			inner_datatype=datatype_searcher.get_datatype_by_key(elem_type_key);
		}
		if(inner_datatype==null) {
			String[] name_split=name.split("]");
			inner_datatype=new StructureDataType(name_split[name_split.length-1]+"_data", (int)size/len);
		}
		array_datatype.add(new ArrayDataType(inner_datatype, len, inner_datatype.getLength()));
		return array_datatype;
	}

	@Override
	protected void parse_datatype() {
		long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		elem_type_key=elem_addr_value-type_base_addr.getOffset();
		slice=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
		len=(int)go_bin.get_address_value(ext_base_addr, pointer_size*2, pointer_size);

		dependence_type_key_list.add(elem_type_key);

		if(check_tflag(tflag, Tflag.Uncommon)) {
			uncommon_base_addr=go_bin.get_address(ext_base_addr, pointer_size*3);
		}
	}
}
