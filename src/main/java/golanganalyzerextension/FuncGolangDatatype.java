package golanganalyzerextension;

import java.util.List;
import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;


class FuncGolangDatatype extends GolangDatatype {
	List<Long> in_type_key=null;
	List<Long> out_type_key=null;

	FuncGolangDatatype(GolangDatatype basic_info, List<Long> in_type_key, List<Long> out_type_key) {
		super(basic_info);
		this.in_type_key=in_type_key;
		this.out_type_key=out_type_key;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		DataType ptr_datatype=new PointerDataType(new VoidDataType(), go_bin.get_pointer_size());
		return ptr_datatype;
	}
}
