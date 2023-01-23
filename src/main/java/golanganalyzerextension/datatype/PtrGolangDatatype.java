package golanganalyzerextension.datatype;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.VoidDataType;
import golanganalyzerextension.DatatypeHolder;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;


public class PtrGolangDatatype extends GolangDatatype {

	private long elem_type_key;

	PtrGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	@Override
	public void make_datatype(DatatypeHolder datatype_searcher) {
		DataType inner_datatype=datatype_searcher.get_datatype_by_key(elem_type_key);
		if(inner_datatype==null) {
			inner_datatype=new VoidDataType();
		}
		datatype=new PointerDataType(inner_datatype, go_bin.get_pointer_size());
	}

	@Override
	void parse_datatype() throws BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

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
