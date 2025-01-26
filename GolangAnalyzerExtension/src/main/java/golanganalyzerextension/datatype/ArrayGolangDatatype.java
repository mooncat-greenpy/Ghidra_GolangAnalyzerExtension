package golanganalyzerextension.datatype;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.ArrayDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import golanganalyzerextension.DatatypeHolder;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;


public class ArrayGolangDatatype extends GolangDatatype {
	private long elem_type_key;
	private int len;

	ArrayGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	@Override
	public void make_datatype(DatatypeHolder datatype_holder) {
		if(len<=0) {
			datatype=new VoidDataType();
			return;
		}
		DataType inner_datatype=datatype_holder.get_datatype_by_key(elem_type_key);
		if(inner_datatype==null) {
			String[] name_split=name.split("]");
			inner_datatype=new StructureDataType(name_split[name_split.length-1]+"_data", (int)size/len);
		}
		datatype=new ArrayDataType(inner_datatype, len, inner_datatype.getLength());
	}

	@Override
	void parse_datatype() throws BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

		long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		elem_type_key=elem_addr_value-type_base_addr.getOffset();
		// long slice=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
		len=(int)go_bin.get_address_value(ext_base_addr, pointer_size*2, pointer_size);

		dependence_type_key_list.add(elem_type_key);

		if(!is_go16 && check_tflag(tflag, Tflag.Uncommon)) {
			uncommon_base_addr=go_bin.get_address(ext_base_addr, pointer_size*3);
		}
	}
}
