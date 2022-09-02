package golanganalyzerextension;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;


class OtherGolangDatatype extends GolangDatatype {
	DataType datatype=null;

	OtherGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16, DataType datatype) {
		super(go_bin, type_base_addr, offset, is_go16);
		this.datatype=datatype;
	}

	@Override
	public DataType get_datatype(DatatypeSearcher datatype_searcher) {
		return datatype;
	}
}
