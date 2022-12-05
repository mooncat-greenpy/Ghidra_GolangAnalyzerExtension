package golanganalyzerextension;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;


public class OtherGolangDatatype extends GolangDatatype {

	private DataType inner_datatype;

	OtherGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16, DataType datatype) {
		super(go_bin, type_base_addr, offset, is_go16);
		inner_datatype=datatype;
	}

	@Override
	public void make_datatype(DatatypeHolder datatype_searcher) {
		datatype=inner_datatype;
	}
}
