package golanganalyzerextension;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.DataTypeConflictException;
import ghidra.program.model.data.IntegerDataType;
import ghidra.program.model.data.LongLongDataType;
import ghidra.program.model.data.PointerDataType;
import ghidra.program.model.data.ShortDataType;
import ghidra.program.model.data.SignedByteDataType;
import ghidra.program.model.data.StructureDataType;
import ghidra.program.model.data.UnsignedCharDataType;
import ghidra.program.model.data.UnsignedIntegerDataType;
import ghidra.program.model.data.UnsignedLongLongDataType;
import ghidra.program.model.data.UnsignedShortDataType;
import ghidra.program.model.data.VoidDataType;
import ghidra.program.model.util.CodeUnitInsertionException;


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

	Address addr=null;
	long key=0;
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

	private boolean init_basic_golang_hardcode_datatype() {
		hardcode_datatype_map=new HashMap<String, DataType>();

		int pointer_size=go_bin.get_pointer_size();
		// reflect/type.go
		StructureDataType _type_datatype=new StructureDataType("hardcord._type", 0);
		_type_datatype.setPackingEnabled(true);
		_type_datatype.setExplicitMinimumAlignment(pointer_size);
		_type_datatype.add(new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()), "size", "");
		_type_datatype.add(new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()), "ptrdata", "");
		_type_datatype.add(new UnsignedIntegerDataType(), "hash", "");
		_type_datatype.add(new UnsignedCharDataType(), "tflag", "");
		_type_datatype.add(new UnsignedCharDataType(), "align", "");
		_type_datatype.add(new UnsignedCharDataType(), "fieldAlign", "");
		_type_datatype.add(new UnsignedCharDataType(), "kind", "");
		_type_datatype.add(new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()), "equal", "");
		_type_datatype.add(new PointerDataType(new UnsignedCharDataType(), go_bin.get_pointer_size()), "gcdata", "");
		_type_datatype.add(new UnsignedIntegerDataType(), "str", "");
		_type_datatype.add(new UnsignedIntegerDataType(), "ptrToThis", "");
		hardcode_datatype_map.put("runtime._type", _type_datatype);

		// runtime/chan.go
		StructureDataType waitq_datatype=new StructureDataType("hardcord.waitq", 0);
		waitq_datatype.setPackingEnabled(true);
		waitq_datatype.setExplicitMinimumAlignment(pointer_size);
		waitq_datatype.add(new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()), "first", "");
		waitq_datatype.add(new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()), "last", "");
		hardcode_datatype_map.put("runtime.waitq", waitq_datatype);

		// runtime/runtime2.go
		StructureDataType mutex_datatype=new StructureDataType("hardcode.mutex", 0);
		mutex_datatype.setPackingEnabled(true);
		mutex_datatype.setExplicitMinimumAlignment(pointer_size);
		// lockRankStruct
		mutex_datatype.add(new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()), "key", "");
		hardcode_datatype_map.put("runtime.mutex", mutex_datatype);


		hardcode_datatype_map.put("bool", new BooleanDataType());
		if(pointer_size==8) {
			hardcode_datatype_map.put("int", new LongLongDataType());
		}else {
			hardcode_datatype_map.put("int", new IntegerDataType());
		}
		hardcode_datatype_map.put("int8", new SignedByteDataType());
		hardcode_datatype_map.put("int16", new ShortDataType());
		hardcode_datatype_map.put("int32", new IntegerDataType());
		hardcode_datatype_map.put("int64", new LongLongDataType());
		if(pointer_size==8) {
			hardcode_datatype_map.put("uint", new UnsignedLongLongDataType());
		}else {
			hardcode_datatype_map.put("uint", new UnsignedIntegerDataType());
		}
		hardcode_datatype_map.put("uint8", new ByteDataType());
		hardcode_datatype_map.put("uint16", new UnsignedShortDataType());
		hardcode_datatype_map.put("uint32", new UnsignedIntegerDataType());
		hardcode_datatype_map.put("uint64", new UnsignedLongLongDataType());
		if(pointer_size==8) {
			hardcode_datatype_map.put("uintptr", new UnsignedLongLongDataType());
		}else {
			hardcode_datatype_map.put("uintptr", new UnsignedIntegerDataType());
		}
		hardcode_datatype_map.put("unsafe.Pointer", new PointerDataType(new VoidDataType(), go_bin.get_pointer_size()));

		return true;
	}

	GolangDatatype(GolangBinary go_bin, Address type_base_addr, long offset, long key, long size, long ptrdata, int hash, int tflag, int align, int field_align, Kind kind, long equal, long gcdata, String name, long ptr_to_this_off) {
		this.go_bin=go_bin;
		if(hardcode_datatype_map==null) {
			init_basic_golang_hardcode_datatype();
		}

		this.addr=go_bin.get_address(type_base_addr, offset);
		this.key=key;
		this.size=size;
		this.ptrdata=ptrdata;
		this.hash=hash;
		this.tflag=tflag;
		this.align=align;
		this.field_align=field_align;
		this.kind=kind;
		this.equal=equal;
		this.gcdata=gcdata;
		this.name=name;
		if(this.name.length()==0) {
			this.name=String.format("not_found_%x", this.key);
		}
		this.ptr_to_this_off=ptr_to_this_off;

		create_type_label_struct(type_base_addr);
	}

	GolangDatatype(GolangDatatype basic_info) {
		this.go_bin=basic_info.go_bin;

		this.addr=basic_info.addr;
		this.key=basic_info.key;
		this.size=basic_info.size;
		this.ptrdata=basic_info.ptrdata;
		this.hash=basic_info.hash;
		this.tflag=basic_info.tflag;
		this.align=basic_info.align;
		this.field_align=basic_info.field_align;
		this.kind=basic_info.kind;
		this.equal=basic_info.equal;
		this.gcdata=basic_info.gcdata;
		this.name=basic_info.name;
		if(this.name.length()==0) {
			this.name=String.format("not_found_%x", this.key);
		}
		this.ptr_to_this_off=basic_info.ptr_to_this_off;
	}

	public Kind get_kind() {
		return kind;
	}

	public String get_name() {
		return name;
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map) {
		return new VoidDataType();
	}

	public DataType get_datatype(Map<Long, GolangDatatype> datatype_map, boolean once) {
		return get_datatype(datatype_map);
	}

	protected DataType get_datatype_by_name(String datatype_name, Map<Long, GolangDatatype> datatype_map) {
		for(Map.Entry<Long, GolangDatatype> entry : datatype_map.entrySet()) {
			GolangDatatype tmp_go_datatype=entry.getValue();
			if(!tmp_go_datatype.get_name().equals(datatype_name)) {
				continue;
			}
			DataType tmp_datatype=entry.getValue().get_datatype(datatype_map);
			if(tmp_datatype.getLength()>0) {
				return tmp_datatype;
			}
		}
		if(hardcode_datatype_map.containsKey(datatype_name)) {
			return hardcode_datatype_map.get(datatype_name);
		}
		return new VoidDataType();
	}

	private void create_type_label_struct(Address type_base_addr) {
		go_bin.create_label(addr, String.format("datatype.%s.%s", get_kind().name(), get_name()));
		try {
			go_bin.create_data(addr, get_datatype_by_name("runtime._type", new HashMap<Long, GolangDatatype>()));
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
}
