package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;


class StructField {
	String name;
	long type_key;
	int offset;

	StructField(String name, long type_key, int offset){
		this.name=name;
		this.type_key=type_key;
		this.offset=offset;
	}
}

class StructGolangDatatype extends GolangDatatype {
	String pkg_name="";
	List<StructField> field_list=null;

	StructGolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		super(go_bin, type_base_addr, offset, is_go16);
	}

	@Override
	public DataType get_datatype(DatatypeSearcher datatype_searcher) {
		StructureDataType structure_datatype=new StructureDataType(name, (int)size);
		structure_datatype.setPackingEnabled(true);
		structure_datatype.setExplicitMinimumAlignment(field_align);
		for(StructField field : field_list) {
			DataType field_datatype=datatype_searcher.get_datatype_by_key(field.type_key);
			if(field_datatype==null) {
				field_datatype=new PointerDataType(new VoidDataType(), go_bin.get_pointer_size());
			}
			if(field_datatype.getLength()>0){
				structure_datatype.insertAtOffset(field.offset, field_datatype, field_datatype.getLength(), field.name, null);
			}
		}
		return structure_datatype;
	}

	@Override
	protected void parse_datatype() {
		long pkg_path_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
		long fields_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
		long fields_len=go_bin.get_address_value(ext_base_addr, pointer_size*2, pointer_size);

		pkg_name="";
		if(pkg_path_addr_value!=0) {
			pkg_name=get_type_string(go_bin.get_address(type_base_addr, pkg_path_addr_value-type_base_addr.getOffset()), 0);
		}
		field_list=new ArrayList<StructField>();
		for(int i=0;i<fields_len;i++) {
			long field_name_addr_value=go_bin.get_address_value(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset(), pointer_size);
			long field_type_addr_value=go_bin.get_address_value(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset()+pointer_size, pointer_size);
			long field_type_key=field_type_addr_value-type_base_addr.getOffset();
			long offset_embed=go_bin.get_address_value(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset()+pointer_size*2, pointer_size);

			String field_name=get_type_string(go_bin.get_address(type_base_addr, field_name_addr_value-type_base_addr.getOffset()), 0);
			dependence_type_key_list.add(field_type_key);
			field_list.add(new StructField(field_name, field_type_key, (int)offset_embed));
		}
	}
}
