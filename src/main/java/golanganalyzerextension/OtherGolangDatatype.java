package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;


class OtherGolangDatatype extends GolangDatatype {
	DataType datatype=null;

	OtherGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16, boolean fix_label, DataType datatype) {
		super(go_bin, type_base_addr, offset, is_go16, fix_label);
		this.datatype=datatype;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		return datatype;
	}
}
