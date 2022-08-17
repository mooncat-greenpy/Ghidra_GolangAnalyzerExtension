package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;


class ChanGolangDatatype extends GolangDatatype {
	long elem_type_key=0;
	long dir=0;

	ChanGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16, boolean fix_label) {
		super(go_bin, type_base_addr, offset, is_go16, fix_label);
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		DataType chan_datatype=new PointerDataType(get_datatype(datatype_map, true), go_bin.get_pointer_size());
		return chan_datatype;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map, boolean once) {
		String struct_name=name;
		if(struct_name.length()>0 && struct_name.endsWith("*")) {
			struct_name=struct_name.substring(0, struct_name.length()-1);
		}

		// runtime/chan.go
		StructureDataType hchan_datatype=new StructureDataType(struct_name, 0);
		hchan_datatype.setPackingEnabled(true);
		hchan_datatype.setExplicitMinimumAlignment(pointer_size);
		hchan_datatype.add(get_datatype_by_name("uint", datatype_map), "qcount", "");
		hchan_datatype.add(get_datatype_by_name("uint", datatype_map), "dataqsiz", "");
		hchan_datatype.add(get_datatype_by_name("unsafe.Pointer", datatype_map), "buf", "");
		hchan_datatype.add(get_datatype_by_name("uint16", datatype_map), "elemsize", "");
		hchan_datatype.add(get_datatype_by_name("uint32", datatype_map), "closed", "");
		hchan_datatype.add(new PointerDataType(get_datatype_by_name("runtime._type", datatype_map), pointer_size), "elemtype", "");
		hchan_datatype.add(get_datatype_by_name("uint", datatype_map), "sendx", "");
		hchan_datatype.add(get_datatype_by_name("uint", datatype_map), "recvx", "");
		hchan_datatype.add(new PointerDataType(get_datatype_by_name("runtime.waitq", datatype_map), pointer_size), "recvq", "");
		hchan_datatype.add(new PointerDataType(get_datatype_by_name("runtime.waitq", datatype_map), pointer_size), "sendq", "");
		hchan_datatype.add(get_datatype_by_name("runtime.mutex", datatype_map), "lock", "");
		return hchan_datatype;
	}

	@Override
	protected void parse_datatype() {
		long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		elem_type_key=elem_addr_value-type_base_addr.getOffset();
		dir=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);

		dependence_type_key_list.add(elem_type_key);
	}
}
