package golanganalyzerextension.datatype;

import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Float4DataType;
import ghidra.program.model.data.Float8DataType;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.StringDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.VoidDataType;
import golanganalyzerextension.DatatypeHolder;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;


public class GolangDatatype {

	GolangBinary go_bin;
	boolean is_go16;
	Address type_base_addr;
	Address addr;
	long key;
	Address ext_base_addr;
	List<Long> dependence_type_key_list;

	long size;
	long ptrdata;
	int hash;
	int tflag;
	int align;
	int field_align;
	Kind kind;
	long equal;
	long gcdata;
	String name;
	long ptr_to_this_off;

	DataType datatype;
	Address uncommon_base_addr;
	UncommonType uncommon_type;

	enum Tflag {
		None, Uncommon, ExtraStar, Named, RegularMemory
	}

	GolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) throws InvalidBinaryStructureException {
		kind=Kind.Invalid;

		try {
			this.go_bin=go_bin;
			this.is_go16=is_go16;
			this.type_base_addr=type_base_addr;
			this.addr=go_bin.get_address(type_base_addr, offset);
			this.key=offset;
			int pointer_size=go_bin.get_pointer_size();
			if(is_go16) {
				this.ext_base_addr=go_bin.get_address(this.addr, pointer_size*7+8);
			} else {
				this.ext_base_addr=go_bin.get_address(this.addr, pointer_size*4+16);
			}
			this.dependence_type_key_list=new ArrayList<Long>();

			uncommon_base_addr=null;
			uncommon_type=null;

			parse_basic_info(offset);;

			datatype=new StructureDataType(name, (int)size>=0?(int)size:0);
		} catch (IllegalArgumentException | BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Invalid type structure: type_addr=%s, offset=%x, message=%s", type_base_addr, offset, e.getMessage()));
		}
	}

	public static GolangDatatype create_by_parsing(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) throws InvalidBinaryStructureException {
		int pointer_size=go_bin.get_pointer_size();

		GolangDatatype go_datatype=new GolangDatatype(go_bin, type_base_addr, offset, is_go16);

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

		return go_datatype;
	}

	public Address get_addr() {
		return addr;
	}

	public long get_size() {
		return size;
	}

	public String get_name() {
		return name;
	}

	public Kind get_kind() {
		return kind;
	}

	public Optional<UncommonType> get_uncommon_type() {
		return Optional.ofNullable(uncommon_type);
	}

	public DataType get_inner_datatype(boolean once) {
		return datatype;
	}

	public StructureDataType get_datatype() {
		if(datatype instanceof StructureDataType) {
			return (StructureDataType)datatype;
		}
		StructureDataType struct_datatype=new StructureDataType(name, 0);
		struct_datatype.add(datatype);
		return struct_datatype;
	}

	public String get_category_path() {
		return String.format("/Golang_%s", get_kind().name());
	}

	public List<Long> get_dependence_type_key_list(){
		return dependence_type_key_list;
	}

	public void modify(DatatypeHolder datatype_searcher) {
		try {
			go_bin.create_label(addr, String.format("datatype.%s.%s", get_kind().name(), get_name()));
			go_bin.create_data(addr, datatype_searcher.get_datatype_by_name("runtime._type"));
			go_bin.set_comment(go_bin.get_address(addr, go_bin.get_pointer_size()*2+4+1*3), ghidra.program.model.listing.CodeUnit.EOL_COMMENT, get_kind().name());
			go_bin.set_comment(go_bin.get_address(addr, go_bin.get_pointer_size()*4+4+1*4), ghidra.program.model.listing.CodeUnit.EOL_COMMENT, get_name());
			if(ptr_to_this_off!=0) {
				go_bin.set_comment(go_bin.get_address(addr, go_bin.get_pointer_size()*4+4*2+1*4), ghidra.program.model.listing.CodeUnit.EOL_COMMENT,
						String.format("%x", type_base_addr.getOffset()+ptr_to_this_off));
			}
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to create datatype: addr=%s, name=%s, message%s", addr, get_name(), e.getMessage()));
		}
	}

	String get_type_string(Address address, int flag) throws InvalidBinaryStructureException {
		boolean is_go117=false;
		if(go_bin.ge_go_version("go1.17beta1")) {
			is_go117=true;
		}

		try {
			String str;
			if(is_go117) {
				int str_size=(int)(go_bin.get_address_value(address, 1, 1));
				str=go_bin.read_string(go_bin.get_address(address, 2), str_size);
			}else {
				int str_size=(int)(go_bin.get_address_value(address, 1, 1)<<8)+(int)(go_bin.get_address_value(address, 2, 1));
				str=go_bin.read_string(go_bin.get_address(address, 3), str_size);
			}
			if(str.length()>0 && check_tflag(flag, Tflag.ExtraStar)) {
				str=str.substring(1);
			}
			return str;
		} catch (BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Get type string: addr=%s", address));
		}
	}

	boolean check_tflag(int flag, Tflag target) {
		if((flag&1<<0)>0 && target==Tflag.Uncommon) {
			return true;
		}
		if((flag&1<<1)>0 && target==Tflag.ExtraStar) {
			return true;
		}
		if((flag&1<<2)>0 && target==Tflag.Named) {
			return true;
		}
		if((flag&1<<3)>0 && target==Tflag.RegularMemory) {
			return true;
		}
		return false;
	}

	private void parse_basic_info(long offset) throws InvalidBinaryStructureException, BinaryAccessException {
		int pointer_size=go_bin.get_pointer_size();

		// runtime/type.go, reflect/type.go
		size=go_bin.get_address_value(type_base_addr, offset, pointer_size);
		ptrdata=go_bin.get_address_value(type_base_addr, offset+pointer_size, pointer_size);
		hash=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*2, 4);
		tflag=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*2+4, 1);
		align=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*2+4+1, 1);
		field_align=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*2+4+1*2, 1);
		int kind_value=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*2+4+1*3, 1)&0x1f;
		equal=go_bin.get_address_value(type_base_addr, offset+pointer_size*2+4+1*4, pointer_size);
		gcdata=go_bin.get_address_value(type_base_addr, offset+pointer_size*3+4+1*4, pointer_size);
		name="";
		ptr_to_this_off=0;
		if(is_go16) {
			name=go_bin.read_string_struct(go_bin.get_address_value(type_base_addr, offset+pointer_size*4+4+1*4, pointer_size), pointer_size);
			long x=go_bin.get_address_value(type_base_addr, offset+pointer_size*5+4+1*4, pointer_size);
			if(x!=0) {
				uncommon_base_addr=go_bin.get_address(x);
			}
			ptr_to_this_off=go_bin.get_address_value(type_base_addr, offset+pointer_size*6+4+1*4, pointer_size);
			if(ptr_to_this_off!=0) {
				ptr_to_this_off-=type_base_addr.getOffset();
			}
		}else {
			int name_off=(int)go_bin.get_address_value(type_base_addr, offset+pointer_size*4+4+1*4, 4);
			if(name_off==0 || !go_bin.is_valid_address(go_bin.get_address(type_base_addr, name_off))) {
				throw new InvalidBinaryStructureException("Failed to get type name: version > go1.6*");
			}
			name=get_type_string(go_bin.get_address(type_base_addr, name_off), tflag);
			ptr_to_this_off=go_bin.get_address_value(type_base_addr, offset+pointer_size*4+4*2+1*4, 4);
		}
		if(name.length()==0) {
			name=String.format("not_found_%x", key);
		}
		if(ptr_to_this_off!=0) {
			dependence_type_key_list.add(ptr_to_this_off);
		}

		if(kind_value>=Kind.MaxKind.ordinal() ||
				(equal!=0 && !go_bin.is_valid_address(equal)) ||
				(gcdata!=0 && !go_bin.is_valid_address(gcdata)) ||
				(ptr_to_this_off!=0 && !go_bin.is_valid_address(go_bin.get_address(type_base_addr, ptr_to_this_off)))) {
			throw new InvalidBinaryStructureException(String.format("Invalid basic type field: kind=%d, equal=%x, gcdata=%x, ptr_to_this_offset=%x", kind_value, equal, gcdata, ptr_to_this_off));
		}
		kind=Kind.values()[kind_value];
	}

	private void parse() {
		try {
			parse_datatype();
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to parse datatype: type_addr=%s, ext_addr=%s, kind=%s, message=%s", type_base_addr, ext_base_addr, kind.name(), e.getMessage()));
		}
		try {
			parse_uncommon();
		} catch (InvalidBinaryStructureException e) {
			Logger.append_message(String.format("Failed to get UncommonType: type_addr=%x message=%s", type_base_addr.getOffset(), e.getMessage()));
		}
	}

	void parse_datatype() throws BinaryAccessException {}

	private void parse_uncommon() throws InvalidBinaryStructureException {
		if(uncommon_base_addr==null) {
			return;
		}
		uncommon_type=new UncommonType(go_bin, uncommon_base_addr, type_base_addr, is_go16);
	}

	public void make_datatype(DatatypeHolder datatype_searcher) {
		datatype=new StructureDataType(name, (int)size);
	}
}
