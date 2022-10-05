package golanganalyzerextension;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.util.CodeUnitInsertionException;
import golanganalyzerextension.StructureManager.Tflag;


enum Kind {
	Invalid,
	Bool, Int, Int8, Int16, Int32, Int64,
	Uint, Uint8, Uint16, Uint32, Uint64,
	Uintptr, Float32, Float64, Complex64, Complex128,
	Array, Chan, Func, Interface, Map,
	Ptr, Slice, String, Struct, UnsafePointer, MaxKind
}

class GolangDatatype {
	static Map<String, DataType> hardcode_datatype_map=null;

	GolangBinary go_bin=null;
	boolean is_go16=false;
	Address type_base_addr=null;
	Address addr=null;
	long key=0;
	int pointer_size=0;
	Address ext_base_addr;
	List<Long> dependence_type_key_list;

	boolean crashed=true;

	long size=0;
	long ptrdata=0;
	int hash=0;
	int tflag=0;
	int align=0;
	int field_align=0;
	Kind kind=Kind.Invalid;
	long equal=0;
	long gcdata=0;
	String name="";
	long ptr_to_this_off=0;

	Address uncommon_base_addr=null;
	Optional<UncommonType> uncommon_type_opt;

	GolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, boolean is_go16) {
		this.crashed=true;
		kind=Kind.Invalid;

		this.go_bin=go_bin;
		this.is_go16=is_go16;
		this.type_base_addr=type_base_addr;
		this.addr=go_bin.get_address(type_base_addr, offset);
		this.key=offset;
		this.pointer_size=go_bin.get_pointer_size();
		if(is_go16) {
			this.ext_base_addr=go_bin.get_address(this.addr, this.pointer_size*7+8);
		} else {
			this.ext_base_addr=go_bin.get_address(this.addr, this.pointer_size*4+16);
		}
		this.dependence_type_key_list=new ArrayList<Long>();

		uncommon_type_opt=Optional.empty();

		if (!parse_basic_info(offset)) {
			return;
		}

		this.crashed=false;
	}

	public Kind get_kind() {
		return kind;
	}

	public String get_name() {
		return name;
	}

	public Optional<UncommonType> get_uncommon_type() {
		return uncommon_type_opt;
	}

	public DataType get_datatype(DatatypeSearcher datatype_searcher) {
		return new VoidDataType();
	}

	public DataType get_datatype(DatatypeSearcher datatype_searcher, boolean once) {
		return get_datatype(datatype_searcher);
	}

	public void modify(DatatypeSearcher datatype_searcher) {
		go_bin.create_label(addr, String.format("datatype.%s.%s", get_kind().name(), get_name()));
		try {
			go_bin.create_data(addr, datatype_searcher.get_datatype_by_name("runtime._type"));
			go_bin.set_comment(go_bin.get_address(addr, go_bin.get_pointer_size()*2+4+1*3), ghidra.program.model.listing.CodeUnit.EOL_COMMENT, get_kind().name());
			go_bin.set_comment(go_bin.get_address(addr, go_bin.get_pointer_size()*4+4+1*4), ghidra.program.model.listing.CodeUnit.EOL_COMMENT, get_name());
			if(ptr_to_this_off!=0) {
				go_bin.set_comment(go_bin.get_address(addr, go_bin.get_pointer_size()*4+4*2+1*4), ghidra.program.model.listing.CodeUnit.EOL_COMMENT,
						String.format("%x", type_base_addr.getOffset()+ptr_to_this_off));
			}
		} catch (CodeUnitInsertionException | DataTypeConflictException e) {
			Logger.append_message(String.format("Failed to create data: %s %x %s", e.getMessage(), addr.getOffset(), get_name()));
		}
	}

	protected String get_type_string(Address address, int flag) {
		boolean is_go117=false;
		if(go_bin.ge_go_version("go1.17beta1")) {
			is_go117=true;
		}

		String str=null;
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
	}

	protected boolean check_tflag(int flag, Tflag target) {
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

	private boolean parse_basic_info(long offset) {
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
			if(name==null) {
				return false;
			}
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
				return false;
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
			return false;
		}
		kind=Kind.values()[kind_value];

		return true;
	}

	public void parse() {
		parse_datatype();
		parse_uncommon();
	}

	protected void parse_datatype() {}

	private void parse_uncommon() {
		if(uncommon_base_addr==null) {
			return;
		}
		uncommon_type_opt=Optional.ofNullable(new UncommonType(go_bin, uncommon_base_addr, type_base_addr, is_go16));
	}
}
