package golanganalyzerextension;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;


public class ChanGolangDatatype extends GolangDatatype {
	private long elem_type_key;

	ChanGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	@Override
	public void make_datatype(DatatypeHolder datatype_holder) {
		String struct_name=name;
		if(struct_name.length()>0 && struct_name.endsWith("*")) {
			struct_name=struct_name.substring(0, struct_name.length()-1);
		}

		int pointer_size=go_bin.get_pointer_size();

		// runtime/chan.go
		StructureDataType hchan_datatype=new StructureDataType(struct_name, 0);
		hchan_datatype.setPackingEnabled(true);
		hchan_datatype.setExplicitMinimumAlignment(pointer_size);
		hchan_datatype.add(datatype_holder.get_datatype_by_name("uint"), "qcount", "");
		hchan_datatype.add(datatype_holder.get_datatype_by_name("uint"), "dataqsiz", "");
		hchan_datatype.add(datatype_holder.get_datatype_by_name("unsafe.Pointer"), "buf", "");
		hchan_datatype.add(datatype_holder.get_datatype_by_name("uint16"), "elemsize", "");
		hchan_datatype.add(datatype_holder.get_datatype_by_name("uint32"), "closed", "");
		hchan_datatype.add(new PointerDataType(datatype_holder.get_datatype_by_name("runtime._type"), pointer_size), "elemtype", "");
		hchan_datatype.add(datatype_holder.get_datatype_by_name("uint"), "sendx", "");
		hchan_datatype.add(datatype_holder.get_datatype_by_name("uint"), "recvx", "");
		hchan_datatype.add(new PointerDataType(datatype_holder.get_datatype_by_name("runtime.waitq"), pointer_size), "recvq", "");
		hchan_datatype.add(new PointerDataType(datatype_holder.get_datatype_by_name("runtime.waitq"), pointer_size), "sendq", "");
		hchan_datatype.add(datatype_holder.get_datatype_by_name("runtime.mutex"), "lock", "");
		datatype=hchan_datatype;
	}

	@Override
	public DataType get_inner_datatype(boolean once) {
		return new PointerDataType(datatype, go_bin.get_pointer_size());
	}

	@Override
	void parse_datatype() {
		int pointer_size=go_bin.get_pointer_size();

		long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		elem_type_key=elem_addr_value-type_base_addr.getOffset();
		// long dir=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);

		dependence_type_key_list.add(elem_type_key);

		if(check_tflag(tflag, Tflag.Uncommon)) {
			uncommon_base_addr=go_bin.get_address(ext_base_addr, pointer_size*2);
		}
	}
}
