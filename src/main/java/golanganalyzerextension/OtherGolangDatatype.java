package golanganalyzerextension;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;


class OtherGolangDatatype extends GolangDatatype {
	StructureDataType datatype=null;

	OtherGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16, DataType datatype) {
		super(go_bin, type_base_addr, offset, is_go16);
		this.datatype=new StructureDataType(name, 0);
		this.datatype.add(datatype);
	}

	@Override
	public StructureDataType get_datatype(DatatypeSearcher datatype_searcher) {
		return datatype;
	}
}
