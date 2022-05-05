package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.data.DataType;


class OtherGolangDatatype extends GolangDatatype {
	DataType datatype=null;

	OtherGolangDatatype(GolangDatatype basic_info, DataType datatype){
		super(basic_info);
		this.datatype=datatype;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		return datatype;
	}
}
