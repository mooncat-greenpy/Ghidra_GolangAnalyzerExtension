package golanganalyzerextension;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;


public class StructureManager {
	GolangBinary go_bin=null;

	DataTypeManager datatype_manager=null;
	Map<Long, GolangDatatype> datatype_map=null;

	boolean ok=false;

	enum Tflag {
		None, Uncommon, ExtraStar, Named, RegularMemory
	}

	public StructureManager(GolangBinary go_bin, Program program, boolean datatype_option) {
		this.go_bin=go_bin;

		if(!datatype_option) {
			return;
		}

		this.datatype_manager=program.getDataTypeManager();
		this.datatype_map=new HashMap<Long, GolangDatatype>();

		if(!init_basig_golang_datatype()) {
			Logger.append_message("Failed to init datatype");
			return;
		}

		for(Object obj : program.getConsumerList()) {
			if(obj instanceof PluginTool) {
				PluginTool plugin_tool=(PluginTool)obj;
				GolangAnalyzerExtensionService service=plugin_tool.getService(GolangAnalyzerExtensionService.class);
				service.store_datatype_map(datatype_map);
			}
		}

		this.ok=true;
		return;
	}

	boolean is_ok() {
		return ok;
	}

	void modify() {
		if(!ok) {
			Logger.append_message("Failed to setup StructureManager");
			return;
		}

		for(Map.Entry<Long, GolangDatatype> entry : datatype_map.entrySet()) {
			try {
				Category category=datatype_manager.createCategory(new CategoryPath(String.format("/Golang_%s", entry.getValue().kind.name())));
				DataType datatype=null;
				datatype=entry.getValue().get_datatype(datatype_map, true);
				if(datatype.getClass().getName()!="ghidra.program.model.data.StructureDataType" && datatype.getClass().getName()!="ghidra.program.model.data.VoidDataType") {
					StructureDataType structure_datatype=new StructureDataType(entry.getValue().get_name(), 0);
					structure_datatype.add(datatype);
					datatype=structure_datatype;
				}
				category.addDataType(datatype, null);
			}catch(Exception e) {
				Logger.append_message(String.format("Error: %s", e.getMessage()));
			}
		}
	}

	boolean init_basig_golang_datatype() {
		boolean is_go116=false;
		boolean is_go118=false;
		if(go_bin.compare_go_version("go1.16beta1")<=0) {
			is_go116=true;
		}
		if(go_bin.compare_go_version("go1.18beta1")<=0) {
			is_go118=true;
		}

		ByteBuffer buffer=ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(go_bin.get_gopclntab_base().getOffset());
		buffer.flip();
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		long reverse=buffer.getLong();
		buffer=ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(reverse);
		byte gopclntab_base_bytes[]=buffer.array();

		int pointer_size=go_bin.get_pointer_size();
		Address base_addr=null;
		while(true) {
			if(pointer_size==4) {
				base_addr=go_bin.find_memory(base_addr, gopclntab_base_bytes, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00});
			}else {
				base_addr=go_bin.find_memory(base_addr, gopclntab_base_bytes, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff});
			}
			if(base_addr==null) {
				break;
			}

			// runtime/symtab.go
			long type_addr_value=0;
			long typelink_addr_value=0;
			long typelink_len=0;
			Address text_addr=null;
			boolean is_go16=false;
			if(is_go118) {
				type_addr_value=go_bin.get_address_value(base_addr, 35*pointer_size, pointer_size);
				typelink_addr_value=go_bin.get_address_value(base_addr, 42*pointer_size, pointer_size);
				typelink_len=go_bin.get_address_value(base_addr, 43*pointer_size, pointer_size);
				text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 22*pointer_size, pointer_size));
			}else if(is_go116) {
				type_addr_value=go_bin.get_address_value(base_addr, 35*pointer_size, pointer_size);
				typelink_addr_value=go_bin.get_address_value(base_addr, 40*pointer_size, pointer_size);
				typelink_len=go_bin.get_address_value(base_addr, 41*pointer_size, pointer_size);
				text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 22*pointer_size, pointer_size));
			}else {
				type_addr_value=go_bin.get_address_value(base_addr, 25*pointer_size, pointer_size);
				typelink_addr_value=go_bin.get_address_value(base_addr, 30*pointer_size, pointer_size);
				typelink_len=go_bin.get_address_value(base_addr, 31*pointer_size, pointer_size);

				Address tmp_type_addr=go_bin.get_address(type_addr_value);
				Address tmp_typelink_addr=go_bin.get_address(typelink_addr_value);
				if(get_basic_type_info(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4), is_go16)==null) {
					type_addr_value=go_bin.get_address_value(base_addr, 25*pointer_size, pointer_size);
					typelink_addr_value=go_bin.get_address_value(base_addr, 27*pointer_size, pointer_size);
					typelink_len=go_bin.get_address_value(base_addr, 28*pointer_size, pointer_size);
					tmp_type_addr=go_bin.get_address(type_addr_value);
					tmp_typelink_addr=go_bin.get_address(typelink_addr_value);
				}
				if(get_basic_type_info(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4), is_go16)==null) {
					is_go16=true;
					typelink_len=go_bin.get_address_value(base_addr, 26*pointer_size, pointer_size);
				}
				text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 12*pointer_size, pointer_size));
			}


			Address type_addr=go_bin.get_address(type_addr_value);
			Address typelink_addr=go_bin.get_address(typelink_addr_value);

			if(!go_bin.is_valid_address(type_addr) || (!go_bin.is_valid_address(typelink_addr) && !is_go16) || !text_addr.equals(go_bin.get_section(".text")))
			{
				base_addr=go_bin.get_address(base_addr, 4);
				if(base_addr==null) {
					break;
				}
				continue;
			}

			for(long i=0;i<typelink_len;i++)
			{
				long offset=0;
				if(is_go16) {
					offset=go_bin.get_address_value(type_addr, pointer_size*i, pointer_size)-type_addr.getOffset();
				}else {
					offset=go_bin.get_address_value(typelink_addr, i*4, 4);
				}
				analyze_type(type_addr, offset, is_go16);
			}

			base_addr=go_bin.get_address(base_addr, 4);
			if(base_addr==null) {
				break;
			}
		}

		if(datatype_map.size()==0)
		{
			return false;
		}
		return true;
	}

	String get_type_string(Address address, int tflag) {
		boolean is_go117=false;
		if(go_bin.compare_go_version("go1.17beta1")<=0) {
			is_go117=true;
		}

		String str=null;
		if(is_go117) {
			int size=(int)(go_bin.get_address_value(address, 1, 1));
			str=go_bin.read_string(go_bin.get_address(address, 2), size);
		}else {
			int size=(int)(go_bin.get_address_value(address, 1, 1)<<8)+(int)(go_bin.get_address_value(address, 2, 1));
			str=go_bin.read_string(go_bin.get_address(address, 3), size);
		}
		if(str.length()>0 && check_tflag(tflag, Tflag.ExtraStar)) {
			str=str.substring(1);
		}
		return str;
	}

	boolean check_tflag(int tflag, Tflag target) {
		if((tflag&1<<0)>0 && target==Tflag.Uncommon) {
			return true;
		}
		if((tflag&1<<1)>0 && target==Tflag.ExtraStar) {
			return true;
		}
		if((tflag&1<<2)>0 && target==Tflag.Named) {
			return true;
		}
		if((tflag&1<<3)>0 && target==Tflag.RegularMemory) {
			return true;
		}
		return false;
	}

	GolangDatatype get_basic_type_info(Address type_base_addr, long offset, boolean is_go16) {
		int pointer_size=go_bin.get_pointer_size();
		// runtime/type.go
		long size=go_bin.get_address_value(type_base_addr, offset, pointer_size);
		long ptrdata=go_bin.get_address_value(type_base_addr, offset+pointer_size, pointer_size);
		int hash=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*2, 4);
		int tflag=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*2+4, 1);
		int align=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*2+4+1, 1);
		int field_align=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*2+4+1*2, 1);
		int kind=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*2+4+1*3, 1)&0x1f;
		long equal=go_bin.get_address_value(type_base_addr, offset+pointer_size*2+4+1*4, pointer_size);
		long gcdata=go_bin.get_address_value(type_base_addr, offset+pointer_size*3+4+1*4, pointer_size);
		String name="";
		long ptr_to_this_off=0;
		if(is_go16) {
			name=go_bin.read_string_struct(go_bin.get_address_value(type_base_addr, offset+pointer_size*4+4+1*4, pointer_size), pointer_size);
			if(name==null) {
				return null;
			}
			long x=go_bin.get_address_value(type_base_addr, offset+pointer_size*5+4+1*4, pointer_size);
			ptr_to_this_off=go_bin.get_address_value(type_base_addr, offset+pointer_size*6+4+1*4, pointer_size);
			if(ptr_to_this_off!=0) {
				ptr_to_this_off-=type_base_addr.getOffset();
			}
		}else {
			int name_off=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*4+4+1*4, 4);
			if(name_off==0 || !go_bin.is_valid_address(go_bin.get_address(type_base_addr, name_off))) {
				return null;
			}
			name=get_type_string(go_bin.get_address(type_base_addr, name_off), tflag);
			ptr_to_this_off=go_bin.get_address_value(type_base_addr, offset+pointer_size*4+4*2+1*4, 4);
		}

		if(kind>=Kind.MaxKind.ordinal() ||
				(equal!=0 && !go_bin.is_valid_address(equal)) ||
				(gcdata!=0 && !go_bin.is_valid_address(gcdata)) ||
				(ptr_to_this_off!=0 && !go_bin.is_valid_address(go_bin.get_address(type_base_addr, ptr_to_this_off)))) {
			return null;
		}

		GolangDatatype basic_info=new GolangDatatype(go_bin, type_base_addr, offset, offset, size, ptrdata, hash, tflag, align, field_align, Kind.values()[kind], equal, gcdata, name, ptr_to_this_off);
		return basic_info;
	}
	boolean analyze_type(Address type_base_addr, long offset, boolean is_go16) {
		if(datatype_map.containsKey(offset)) {
			return true;
		}

		int pointer_size=go_bin.get_pointer_size();

		// reflect/type.go
		GolangDatatype go_datatype=get_basic_type_info(type_base_addr, offset, is_go16);
		if(go_datatype==null) {
			return false;
		}
		datatype_map.put(offset, go_datatype);

		Address ext_base_addr=go_bin.get_address(type_base_addr, offset+pointer_size*4+16);
		if(go_datatype.kind==Kind.Bool) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, new BooleanDataType()));
		}else if(go_datatype.kind==Kind.Int) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_signed_number_datatype(pointer_size)));
		}else if(go_datatype.kind==Kind.Int8) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_signed_number_datatype(1)));
		}else if(go_datatype.kind==Kind.Int16) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_signed_number_datatype(2)));
		}else if(go_datatype.kind==Kind.Int32) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_signed_number_datatype(4)));
		}else if(go_datatype.kind==Kind.Int64) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_signed_number_datatype(8)));
		}else if(go_datatype.kind==Kind.Uint) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_unsigned_number_datatype(pointer_size)));
		}else if(go_datatype.kind==Kind.Uint8) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_unsigned_number_datatype(1)));
		}else if(go_datatype.kind==Kind.Uint16) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_unsigned_number_datatype(2)));
		}else if(go_datatype.kind==Kind.Uint32) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_unsigned_number_datatype(4)));
		}else if(go_datatype.kind==Kind.Uint64) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_unsigned_number_datatype(8)));
		}else if(go_datatype.kind==Kind.Uintptr) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, go_bin.get_unsigned_number_datatype(pointer_size)));
		}else if(go_datatype.kind==Kind.Float32) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, new Float4DataType()));
		}else if(go_datatype.kind==Kind.Float64) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, new Float8DataType()));
		}else if(go_datatype.kind==Kind.Complex64) {
			StructureDataType complex64_datatype=new StructureDataType("complex64", 0);
			complex64_datatype.setPackingEnabled(true);
			complex64_datatype.setExplicitMinimumAlignment(go_datatype.align);
			complex64_datatype.add(new Float4DataType(), "re", null);
			complex64_datatype.add(new Float4DataType(), "im", null);
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, complex64_datatype));
		}else if(go_datatype.kind==Kind.Complex128) {
			StructureDataType complex128_datatype=new StructureDataType("complex128", 0);
			complex128_datatype.setPackingEnabled(true);
			complex128_datatype.setExplicitMinimumAlignment(go_datatype.align);
			complex128_datatype.add(new Float8DataType(), "re", null);
			complex128_datatype.add(new Float8DataType(), "im", null);
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, complex128_datatype));
		}else if(go_datatype.kind==Kind.Array) {
			long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
			long slice=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
			long len=go_bin.get_address_value(ext_base_addr, pointer_size*2, pointer_size);
			if(elem_addr_value!=0) {
				analyze_type(type_base_addr, elem_addr_value-type_base_addr.getOffset(), is_go16);
			}
			datatype_map.replace(offset, new ArrayGolangDatatype(go_datatype, elem_addr_value-type_base_addr.getOffset(), slice, len));
		}else if(go_datatype.kind==Kind.Chan) {
			long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
			long dir=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
			if(elem_addr_value!=0) {
				analyze_type(type_base_addr, elem_addr_value-type_base_addr.getOffset(), is_go16);
			}
			datatype_map.replace(offset, new ChanGolangDatatype(go_datatype, elem_addr_value-type_base_addr.getOffset(), dir));
		}else if(go_datatype.kind==Kind.Func) {
			int in_len=(short)go_bin.get_address_value(ext_base_addr, 2);
			int out_len=(short)go_bin.get_address_value(ext_base_addr, 2, 2);
			out_len=(short)(out_len&0x1f);
			List<Long> in_type_offset_list = new ArrayList<Long>();
			List<Long> out_type_offset_list = new ArrayList<Long>();
			for(int i=0;i<in_len;i++) {
				long in_type_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size+i*pointer_size, pointer_size);
				if(in_type_addr_value!=0) {
					analyze_type(type_base_addr, in_type_addr_value-type_base_addr.getOffset(), is_go16);
				}
				in_type_offset_list.add(in_type_addr_value-type_base_addr.getOffset());
			}
			for(int i=0;i<out_len;i++) {
				long out_type_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size+in_len*pointer_size+i*pointer_size, pointer_size);
				if(out_type_addr_value>type_base_addr.getOffset()) {
					analyze_type(type_base_addr, out_type_addr_value-type_base_addr.getOffset(), is_go16);
				}
				out_type_offset_list.add(out_type_addr_value-type_base_addr.getOffset());
			}
			datatype_map.replace(offset, new FuncGolangDatatype(go_datatype, in_type_offset_list, out_type_offset_list));
		}else if(go_datatype.kind==Kind.Interface) {
			long pkg_path_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
			long methods_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
			long methods_len=go_bin.get_address_value(ext_base_addr, pointer_size*2, pointer_size);

			String pkg_name="";
			if(pkg_path_addr_value!=0) {
				pkg_name=get_type_string(go_bin.get_address(type_base_addr, pkg_path_addr_value-type_base_addr.getOffset()), 0);
			}
			List<String> method_name_list = new ArrayList<String>();
			List<Long> method_type_offset_list = new ArrayList<Long>();
			for(int i=0;i<methods_len;i++) {
				long method_name_addr_value=go_bin.get_address_value(type_base_addr, methods_addr_value+i*2*4-type_base_addr.getOffset(), 4);
				long method_type_offset=go_bin.get_address_value(type_base_addr, methods_addr_value+i*2*4-type_base_addr.getOffset()+4, 4);

				String method_name="";
				if(method_name_addr_value!=0) {
					method_name=get_type_string(go_bin.get_address(type_base_addr, method_name_addr_value), 0);
				}
				if(method_type_offset!=0)
				{
					analyze_type(type_base_addr, method_type_offset, is_go16);
				}
				method_name_list.add(method_name);
				method_type_offset_list.add(method_type_offset);
			}
			datatype_map.replace(offset, new InterfaceGolangDatatype(go_datatype, pkg_name, method_name_list, method_type_offset_list));
		}else if(go_datatype.kind==Kind.Map) {
			long key_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
			long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
			// ...
			if(key_addr_value!=0) {
				analyze_type(type_base_addr, key_addr_value-type_base_addr.getOffset(), is_go16);
			}
			if(elem_addr_value!=0) {
				analyze_type(type_base_addr, elem_addr_value-type_base_addr.getOffset(), is_go16);
			}
			datatype_map.replace(offset, new MapGolangDatatype(go_datatype, key_addr_value-type_base_addr.getOffset(), elem_addr_value));
		}else if(go_datatype.kind==Kind.Ptr) {
			long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
			if(elem_addr_value!=0) {
				analyze_type(type_base_addr, elem_addr_value-type_base_addr.getOffset(), is_go16);
			}
			datatype_map.replace(offset, new PtrGolangDatatype(go_datatype, elem_addr_value-type_base_addr.getOffset()));
		}else if(go_datatype.kind==Kind.Slice) {
			long elem_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
			if(elem_addr_value!=0) {
				analyze_type(type_base_addr, elem_addr_value-type_base_addr.getOffset(), is_go16);
			}
			datatype_map.replace(offset, new SliceGolangDatatype(go_datatype, elem_addr_value-type_base_addr.getOffset()));
		}else if(go_datatype.kind==Kind.String) {
			StructureDataType string_datatype=new StructureDataType("string", 0);
			string_datatype.setPackingEnabled(true);
			string_datatype.setExplicitMinimumAlignment(go_datatype.align);
			string_datatype.add(new PointerDataType(new StringDataType(), pointer_size), "__data", null);
			string_datatype.add(new IntegerDataType(), "__length", null);
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, string_datatype));
		}else if(go_datatype.kind==Kind.Struct) {
			long pkg_path_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size);
			long fields_addr_value=go_bin.get_address_value(ext_base_addr, pointer_size, pointer_size);
			long field_len=go_bin.get_address_value(ext_base_addr, pointer_size*2, pointer_size);

			String pkg_name_string="";
			if(pkg_path_addr_value!=0) {
				pkg_name_string=get_type_string(go_bin.get_address(type_base_addr, pkg_path_addr_value-type_base_addr.getOffset()), 0);
			}
			List<String> field_name_list = new ArrayList<String>();
			List<Long> field_type_offset_list = new ArrayList<Long>();
			for(int i=0;i<field_len;i++) {
				long field_name_addr_value=go_bin.get_address_value(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset(), pointer_size);
				long field_type_addr_value=go_bin.get_address_value(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset()+pointer_size, pointer_size);
				long offset_embed=go_bin.get_address_value(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset()+pointer_size*2, pointer_size);

				String field_name=get_type_string(go_bin.get_address(type_base_addr, field_name_addr_value-type_base_addr.getOffset()), 0);
				analyze_type(type_base_addr, field_type_addr_value-type_base_addr.getOffset(), is_go16);
				field_name_list.add(field_name);
				field_type_offset_list.add(field_type_addr_value-type_base_addr.getOffset());
			}
			datatype_map.replace(offset, new StructGolangDatatype(go_datatype, pkg_name_string, field_name_list, field_type_offset_list));
		}else if(go_datatype.kind==Kind.UnsafePointer) {
			datatype_map.replace(offset, new OtherGolangDatatype(go_datatype, new PointerDataType(new VoidDataType(), go_bin.get_pointer_size())));
		}

		if(go_datatype.ptr_to_this_off!=0) {
			analyze_type(type_base_addr, go_datatype.ptr_to_this_off, is_go16);
		}
		return true;
	}
}
