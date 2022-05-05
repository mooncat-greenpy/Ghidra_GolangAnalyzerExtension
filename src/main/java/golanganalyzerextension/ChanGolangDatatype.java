package golanganalyzerextension;

import java.util.Map;

import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;


class ChanGolangDatatype extends GolangDatatype {
	long elem_type_key=0;
	long dir=0;

	ChanGolangDatatype(GolangDatatype basic_info, long elem_type_key, long dir) {
		super(basic_info);
		this.elem_type_key=elem_type_key;
		this.dir=dir;
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
		int pointer_size=go_bin.get_pointer_size();
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
}
