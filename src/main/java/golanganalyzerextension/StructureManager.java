package golanganalyzerextension;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;


public class StructureManager {
	GolangBinary go_bin=null;
	GolangAnalyzerExtensionService service=null;

	DataTypeManager datatype_manager=null;
	Map<Long, GolangDatatype> datatype_map=null;
	boolean is_go16=false;

	boolean ok=false;

	enum Tflag {
		None, Uncommon, ExtraStar, Named, RegularMemory
	}

	public StructureManager(GolangBinary go_bin, Program program, GolangAnalyzerExtensionService service, boolean datatype_option) {
		this.go_bin=go_bin;
		this.service=service;

		if(!datatype_option) {
			return;
		}

		this.datatype_manager=program.getDataTypeManager();
		this.datatype_map=new HashMap<Long, GolangDatatype>();

		if(!init_basig_golang_datatype()) {
			Logger.append_message("Failed to init datatype");
			return;
		}

		service.store_datatype_map(datatype_map);

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

		DatatypeSearcher datatype_searcher=new DatatypeSearcher(service, go_bin, is_go16);
		for(long key : datatype_searcher.get_key_set()) {
			try {
				GolangDatatype go_datatype=datatype_searcher.get_go_datatype_by_key(key);
				go_datatype.modify(datatype_searcher);

				Category category=datatype_manager.createCategory(new CategoryPath(String.format("/Golang_%s", go_datatype.kind.name())));
				category.addDataType(go_datatype.get_datatype(datatype_searcher, true), null);
			}catch(Exception e) {
				Logger.append_message(String.format("Error: %s", e.getMessage()));
			}
		}
	}

	boolean init_basig_golang_datatype() {
		boolean is_go116=false;
		boolean is_go118=false;
		if(go_bin.ge_go_version("go1.16beta1")) {
			is_go116=true;
		}
		if(go_bin.ge_go_version("go1.18beta1")) {
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
			is_go16=false;

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
				GolangDatatype tmp_datatype=new GolangDatatype(go_bin, tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4), is_go16);
				if(tmp_datatype.crashed) {
					type_addr_value=go_bin.get_address_value(base_addr, 25*pointer_size, pointer_size);
					typelink_addr_value=go_bin.get_address_value(base_addr, 27*pointer_size, pointer_size);
					typelink_len=go_bin.get_address_value(base_addr, 28*pointer_size, pointer_size);
					tmp_type_addr=go_bin.get_address(type_addr_value);
					tmp_typelink_addr=go_bin.get_address(typelink_addr_value);
				}
				tmp_datatype=new GolangDatatype(go_bin, tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4), is_go16);
				if(tmp_datatype.crashed) {
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
				analyze_type(type_addr, offset);
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
		if(go_bin.ge_go_version("go1.17beta1")) {
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

	boolean analyze_type(Address type_base_addr, long offset) {
		if(datatype_map.containsKey(offset)) {
			return true;
		}

		int pointer_size=go_bin.get_pointer_size();

		GolangDatatype go_datatype=new GolangDatatype(go_bin, type_base_addr, offset, is_go16);
		if(go_datatype.crashed) {
			return false;
		}
		datatype_map.put(offset, go_datatype);

		if(go_datatype.kind==Kind.Bool) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, new BooleanDataType());
		}else if(go_datatype.kind==Kind.Int) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_signed_number_datatype(pointer_size));
		}else if(go_datatype.kind==Kind.Int8) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_signed_number_datatype(1));
		}else if(go_datatype.kind==Kind.Int16) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_signed_number_datatype(2));
		}else if(go_datatype.kind==Kind.Int32) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_signed_number_datatype(4));
		}else if(go_datatype.kind==Kind.Int64) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_signed_number_datatype(8));
		}else if(go_datatype.kind==Kind.Uint) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_unsigned_number_datatype(pointer_size));
		}else if(go_datatype.kind==Kind.Uint8) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_unsigned_number_datatype(1));
		}else if(go_datatype.kind==Kind.Uint16) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_unsigned_number_datatype(2));
		}else if(go_datatype.kind==Kind.Uint32) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_unsigned_number_datatype(4));
		}else if(go_datatype.kind==Kind.Uint64) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_unsigned_number_datatype(8));
		}else if(go_datatype.kind==Kind.Uintptr) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, go_bin.get_unsigned_number_datatype(pointer_size));
		}else if(go_datatype.kind==Kind.Float32) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, new Float4DataType());
		}else if(go_datatype.kind==Kind.Float64) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, new Float8DataType());
		}else if(go_datatype.kind==Kind.Complex64) {
			StructureDataType complex64_datatype=new StructureDataType("complex64", 0);
			complex64_datatype.setPackingEnabled(true);
			complex64_datatype.setExplicitMinimumAlignment(go_datatype.align);
			complex64_datatype.add(new Float4DataType(), "re", null);
			complex64_datatype.add(new Float4DataType(), "im", null);
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, complex64_datatype);
		}else if(go_datatype.kind==Kind.Complex128) {
			StructureDataType complex128_datatype=new StructureDataType("complex128", 0);
			complex128_datatype.setPackingEnabled(true);
			complex128_datatype.setExplicitMinimumAlignment(go_datatype.align);
			complex128_datatype.add(new Float8DataType(), "re", null);
			complex128_datatype.add(new Float8DataType(), "im", null);
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, complex128_datatype);
		}else if(go_datatype.kind==Kind.Array) {
			go_datatype=new ArrayGolangDatatype(go_bin, type_base_addr, offset, is_go16);
		}else if(go_datatype.kind==Kind.Chan) {
			go_datatype=new ChanGolangDatatype(go_bin, type_base_addr, offset, is_go16);
		}else if(go_datatype.kind==Kind.Func) {
			go_datatype=new FuncGolangDatatype(go_bin, type_base_addr, offset, is_go16);
		}else if(go_datatype.kind==Kind.Interface) {
			go_datatype=new InterfaceGolangDatatype(go_bin, type_base_addr, offset, is_go16);
		}else if(go_datatype.kind==Kind.Map) {
			go_datatype=new MapGolangDatatype(go_bin, type_base_addr, offset, is_go16);
		}else if(go_datatype.kind==Kind.Ptr) {
			go_datatype=new PtrGolangDatatype(go_bin, type_base_addr, offset, is_go16);
		}else if(go_datatype.kind==Kind.Slice) {
			go_datatype=new SliceGolangDatatype(go_bin, type_base_addr, offset, is_go16);
		}else if(go_datatype.kind==Kind.String) {
			StructureDataType string_datatype=new StructureDataType("string", 0);
			string_datatype.setPackingEnabled(true);
			string_datatype.setExplicitMinimumAlignment(go_datatype.align);
			string_datatype.add(new PointerDataType(new StringDataType(), pointer_size), "__data", null);
			string_datatype.add(new IntegerDataType(), "__length", null);
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, string_datatype);
		}else if(go_datatype.kind==Kind.Struct) {
			go_datatype=new StructGolangDatatype(go_bin, type_base_addr, offset, is_go16);
		}else if(go_datatype.kind==Kind.UnsafePointer) {
			go_datatype=new OtherGolangDatatype(go_bin, type_base_addr, offset, is_go16, new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()));
		}
		go_datatype.parse();
		for(long dependence_type_key : go_datatype.dependence_type_key_list) {
			analyze_type(type_base_addr, dependence_type_key);
		}
		datatype_map.replace(offset, go_datatype);

		return true;
	}
}
