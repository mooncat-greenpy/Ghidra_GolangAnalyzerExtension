package golanganalyzerextension;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.util.importer.MessageLog;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import ghidra.program.model.util.CodeUnitInsertionException;
import ghidra.util.task.TaskMonitor;


public class StructureManager extends GolangBinary {
	DataTypeManager datatype_manager=null;
	Map<String, DataType> hardcode_datatype_map=null;
	Map<String, Long> name_to_type_map=null;
	Map<Long, BasicTypeInfo> basic_type_info_map=null;

	enum Kind {
		Invalid,
		Bool, Int, Int8, Int16, Int32, Int64,
		Uint, Uint8, Uint16, Uint32, Uint64,
		Uintptr, Float32, Float64, Complex64, Complex128,
		Array, Chan, Func, Interface, Map,
		Ptr, Slice, String, Struct, UnsafePointer, MaxKind
	}
	enum Tflag {
		None, Uncommon, ExtraStar, Named, RegularMemory
	}

	class BasicTypeInfo {
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
		BasicTypeInfo(Address addr, long key, long size, long ptrdata, int hash, int tflag, int align, int field_align, Kind kind, long equal, long gcdata, String name) {
			this.addr=addr;
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
		}
		BasicTypeInfo(BasicTypeInfo basic_info) {
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
		}
		public String get_name() {
			return name;
		}
		public DataType get_datatype() {
			return new VoidDataType();
		}
		public DataType get_datatype(boolean once) {
			return get_datatype();
		}
	}
	class ArrayTypeInfo extends BasicTypeInfo {
		long elem_type_key=0;
		long slice=0;
		long len=0;
		ArrayTypeInfo(BasicTypeInfo basic_info, long elem_type_key, long slice, long len) {
			super(basic_info);
			this.elem_type_key=elem_type_key;
			this.slice=slice;
			this.len=len;
		}
		public DataType get_datatype() {
			if(len==0) {
				return new VoidDataType();
			}
			DataType inner_datatype=new UnsignedCharDataType();
			if(basic_type_info_map.containsKey(elem_type_key)) {
				inner_datatype=basic_type_info_map.get(elem_type_key).get_datatype();
			}
			ArrayDataType array_datatype=new ArrayDataType(inner_datatype, (int)len, inner_datatype.getLength());
			return array_datatype;
		}
	}
	class ChanTypeInfo extends BasicTypeInfo {
		long elem_type_key=0;
		long dir=0;
		ChanTypeInfo(BasicTypeInfo basic_info, long elem_type_key, long dir) {
			super(basic_info);
			this.elem_type_key=elem_type_key;
			this.dir=dir;
		}
		public DataType get_datatype() {
			// runtime/chan.go
			StructureDataType hchan_datatype=new StructureDataType(name, 0);
			hchan_datatype.setMinimumAlignment(pointer_size);
			hchan_datatype.add(get_datatype_by_name("uint"), "qcount", "");
			hchan_datatype.add(get_datatype_by_name("uint"), "dataqsiz", "");
			hchan_datatype.add(get_datatype_by_name("unsafe.Pointer"), "buf", "");
			hchan_datatype.add(get_datatype_by_name("uint16"), "elemsize", "");
			hchan_datatype.add(get_datatype_by_name("uint32"), "closed", "");
			hchan_datatype.add(new PointerDataType(get_datatype_by_name("_type")), "elemtype", "");
			hchan_datatype.add(get_datatype_by_name("uint"), "sendx", "");
			hchan_datatype.add(get_datatype_by_name("uint"), "recvx", "");
			hchan_datatype.add(new PointerDataType(get_datatype_by_name("waitq")), "recvq", "");
			hchan_datatype.add(new PointerDataType(get_datatype_by_name("waitq")), "sendq", "");
			hchan_datatype.add(get_datatype_by_name("mutex"), "lock", "");
			DataType chan_datatype=new PointerDataType(hchan_datatype, pointer_size);
			return chan_datatype;
		}
	}
	class FuncTypeInfo extends BasicTypeInfo {
		List<Long> in_type_key=null;
		List<Long> out_type_key=null;
		FuncTypeInfo(BasicTypeInfo basic_info, List<Long> in_type_key, List<Long> out_type_key) {
			super(basic_info);
			this.in_type_key=in_type_key;
			this.out_type_key=out_type_key;
		}
		public DataType get_datatype() {
			DataType ptr_datatype=new PointerDataType(new VoidDataType(), pointer_size);
			return ptr_datatype;
		}
	}
	class InterfaceTypeInfo extends BasicTypeInfo {
		String pkg_name="";
		List<String> methods_name_list=null;
		List<Long> methods_type_key_list=null;
		InterfaceTypeInfo(BasicTypeInfo basic_info, String pkg_name, List<String> methods_name_list, List<Long> methods_type_key_list) {
			super(basic_info);
			this.pkg_name=pkg_name;
			this.methods_name_list=methods_name_list;
			this.methods_type_key_list=methods_type_key_list;
		}
		public DataType get_datatype() {
			// runtime/iface.go
			StructureDataType interface_datatype=new StructureDataType(name, 0);
			interface_datatype.setMinimumAlignment(pointer_size);
			interface_datatype.add(new PointerDataType(get_datatype_by_name("_type")), "tab", "");
			interface_datatype.add(new PointerDataType(), "data", "");
			return interface_datatype;
		}
	}
	class MapTypeInfo extends BasicTypeInfo {
		long key_type_key=0;
		long elem_type_key=0;
		MapTypeInfo(BasicTypeInfo basic_info, long key_type_key, long elem_type_key) {
			super(basic_info);
			this.key_type_key=key_type_key;
			this.elem_type_key=elem_type_key;
		}
		public DataType get_datatype() {
			// runtime/map.go
			StructureDataType hmap_datatype=new StructureDataType(name, 0);
			hmap_datatype.setMinimumAlignment(pointer_size);
			hmap_datatype.add(get_datatype_by_name("int"), "count", "");
			hmap_datatype.add(get_datatype_by_name("uint8"), "flags", "");
			hmap_datatype.add(get_datatype_by_name("uint8"), "B", "");
			hmap_datatype.add(get_datatype_by_name("uint16"), "noverflow", "");
			hmap_datatype.add(get_datatype_by_name("uint32"), "hash0", "");
			hmap_datatype.add(get_datatype_by_name("unsafe.Pointer"), "buckets", "");
			hmap_datatype.add(get_datatype_by_name("unsafe.Pointer"), "oldbuckets", "");
			hmap_datatype.add(get_datatype_by_name("uintptr"), "nevacuate", "");
			hmap_datatype.add(new PointerDataType(), "extra", "");
			DataType map_datatype=new PointerDataType(hmap_datatype, pointer_size);
			return map_datatype;
		}
	}
	class PtrTypeInfo extends BasicTypeInfo {
		long elem_type_key=0;
		PtrTypeInfo(BasicTypeInfo basic_info, long elem_type_key) {
			super(basic_info);
			this.elem_type_key=elem_type_key;
		}
		public DataType get_datatype() {
			return new PointerDataType();
		}
		public DataType get_datatype(boolean once) {
			if(!once) {
				return new PointerDataType();
			}
			DataType inner_datatype=new VoidDataType();
			if(basic_type_info_map.containsKey(elem_type_key)) {
				inner_datatype=basic_type_info_map.get(elem_type_key).get_datatype();
			}
			DataType ptr_datatype=new PointerDataType(inner_datatype, pointer_size);
			return ptr_datatype;
		}
	}
	class SliceTypeInfo extends BasicTypeInfo {
		long elem_type_key=0;
		SliceTypeInfo(BasicTypeInfo basic_info, long elem_type_key) {
			super(basic_info);
			this.elem_type_key=elem_type_key;
		}
		public DataType get_datatype() {
			DataType inner_datatype=new PointerDataType(new VoidDataType(), pointer_size);
			if(basic_type_info_map.containsKey(elem_type_key)) {
				inner_datatype=basic_type_info_map.get(elem_type_key).get_datatype();
			}
			// cmd/cgo/out.go
			StructureDataType slice_datatype=new StructureDataType(name, 0);
			slice_datatype.setMinimumAlignment(pointer_size);
			slice_datatype.add(new PointerDataType(inner_datatype, pointer_size), "__values", null);
			slice_datatype.add(get_datatype_by_name("uintptr"), "__count", null);
			slice_datatype.add(get_datatype_by_name("uintptr"), "__capacity", null);
			return slice_datatype;
		}
	}
	class StructTypeInfo extends BasicTypeInfo {
		String pkg_name="";
		int field_alignment=0;
		List<String> field_name_list=null;
		List<Long> field_type_key_list=null;
		StructTypeInfo(BasicTypeInfo basic_info, String pkg_name, int field_alignment, List<String> field_name_list, List<Long> field_type_key_list) {
			super(basic_info);
			this.pkg_name=pkg_name;
			this.field_alignment=field_alignment;
			this.field_name_list=field_name_list;
			this.field_type_key_list=field_type_key_list;
		}
		public DataType get_datatype() {
			StructureDataType structure_datatype=new StructureDataType(name, 0);
			structure_datatype.setMinimumAlignment(field_alignment);
			for(int i=0;i<field_name_list.size();i++) {
				long field_key=field_type_key_list.get(i);
				DataType field_datatype=new PointerDataType(new VoidDataType(), field_alignment);
				if(basic_type_info_map.containsKey(field_key)) {
					field_datatype=basic_type_info_map.get(field_key).get_datatype();
				}
				structure_datatype.add(field_datatype, field_name_list.get(i), null);
			}
			return structure_datatype;
		}
	}
	class OtherTypeInfo extends BasicTypeInfo {
		DataType datatype=null;
		OtherTypeInfo(BasicTypeInfo basic_info, DataType datatype){
			super(basic_info);
			this.datatype=datatype;
		}
		public DataType get_datatype() {
			return datatype;
		}
	}

	public StructureManager(Program program, TaskMonitor monitor, MessageLog log, boolean debugmode) {
		super(program, monitor, log, debugmode);

		this.datatype_manager=program.getDataTypeManager();
		hardcode_datatype_map=new HashMap<String, DataType>();
		name_to_type_map=new HashMap<String, Long>();
		basic_type_info_map=new HashMap<Long, BasicTypeInfo>();

		if(!init_gopclntab()) {
			return;
		}

		if(!init_basig_golang_hardcode_datatype()) {
			return;
		}

		if(!init_basig_golang_datatype()) {
			return;
		}

		ok=true;
		return;
	}

	void modify() {
		if(!ok) {
			append_message("Failed to setup StructureManager");
			return;
		}

		for(Map.Entry<Long, BasicTypeInfo> entry : basic_type_info_map.entrySet()) {
			Category category=datatype_manager.createCategory(new CategoryPath(String.format("/Golang_%s", entry.getValue().kind.name())));
			DataType datatype=null;
			if(entry.getValue().kind==Kind.Ptr) {
				datatype=entry.getValue().get_datatype(true);
			}else {
				datatype=entry.getValue().get_datatype();
			}
			if(datatype.getClass().getName()!="ghidra.program.model.data.StructureDataType" && datatype.getClass().getName()!="ghidra.program.model.data.VoidDataType") {
				StructureDataType structure_datatype=new StructureDataType(entry.getValue().get_name(), 0);
				structure_datatype.add(datatype);
				datatype=structure_datatype;
			}
			category.addDataType(datatype, null);
		}
	}

	DataType get_datatype_by_name(String name) {
		if(name_to_type_map.containsKey(name) && basic_type_info_map.containsKey(name_to_type_map.get(name))) {
			return basic_type_info_map.get(name_to_type_map.get(name)).get_datatype();
		}
		if(hardcode_datatype_map.containsKey(name)) {
			return hardcode_datatype_map.get(name);
		}
		return new VoidDataType();
	}

	boolean init_basig_golang_hardcode_datatype() {
		// reflect/type.go
		StructureDataType _type_datatype=new StructureDataType("_type", 0);
		_type_datatype.setMinimumAlignment(pointer_size);
		_type_datatype.add(new PointerDataType(), "size", "");
		_type_datatype.add(new PointerDataType(), "ptrdata", "");
		_type_datatype.add(new UnsignedIntegerDataType(), "hash", "");
		_type_datatype.add(new UnsignedCharDataType(), "tflag", "");
		_type_datatype.add(new UnsignedCharDataType(), "align", "");
		_type_datatype.add(new UnsignedCharDataType(), "fieldAlign", "");
		_type_datatype.add(new UnsignedCharDataType(), "kind", "");
		_type_datatype.add(new PointerDataType(), "equal", "");
		_type_datatype.add(new PointerDataType(new UnsignedCharDataType()), "gcdata", "");
		_type_datatype.add(new UnsignedIntegerDataType(), "str", "");
		_type_datatype.add(new UnsignedIntegerDataType(), "ptrToThis", "");
		hardcode_datatype_map.put("_type", _type_datatype);

		// runtime/chan.go
		StructureDataType waitq_datatype=new StructureDataType("waitq", 0);
		waitq_datatype.setMinimumAlignment(pointer_size);
		waitq_datatype.add(new PointerDataType(), "first", "");
		waitq_datatype.add(new PointerDataType(), "last", "");
		hardcode_datatype_map.put("waitq", waitq_datatype);

		// runtime/runtime2.go
		StructureDataType mutex_datatype=new StructureDataType("mutex", 0);
		mutex_datatype.setMinimumAlignment(pointer_size);
		// lockRankStruct
		mutex_datatype.add(new PointerDataType(), "key", "");
		hardcode_datatype_map.put("mutex", mutex_datatype);

		return true;
	}

	boolean init_basig_golang_datatype() {
		ByteBuffer buffer=ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(gopclntab_base.getOffset());
		buffer.flip();
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		long reverse=buffer.getLong();
		buffer=ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(reverse);
		byte gopclntab_base_bytes[]=buffer.array();

		Address base_addr=null;
		while(true) {
			if(pointer_size==4) {
				base_addr=memory.findBytes(base_addr, gopclntab_base_bytes, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff}, true, monitor);
			}else {
				base_addr=memory.findBytes(base_addr, gopclntab_base_bytes, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff}, true, monitor);
			}
			if(base_addr==null) {
				return false;
			}

			// runtime/symtab.go
			long type_addr_value=get_address_value(get_address(base_addr, 25*pointer_size), pointer_size);
			long typelink_addr_value=get_address_value(get_address(base_addr, 30*pointer_size), pointer_size);
			long typelink_len=get_address_value(get_address(base_addr, 31*pointer_size), pointer_size);

			Address type_addr=program.getAddressFactory().getAddress(String.format("%x", type_addr_value));
			Address typelink_addr=program.getAddressFactory().getAddress(String.format("%x", typelink_addr_value));

			for(long i=0;i<typelink_len;i++)
			{
				long offset=get_address_value(get_address(typelink_addr, i*4), 4);
				analyze_type(type_addr, offset);
			}

			base_addr=get_address(base_addr, 4);
			if(base_addr==null) {
				return false;
			}
			break;
		}
		return true;
	}

	String get_type_string(Address address, int tflag) {
		int size=(int)(get_address_value(get_address(address, 1), 1)<<8)+(int)(get_address_value(get_address(address, 2), 1));
		String str=read_string(get_address(address, 3), size);
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
		if(basic_type_info_map.containsKey(offset)) {
			return true;
		}
		// reflect/type.go
		long size=get_address_value(get_address(type_base_addr, offset), pointer_size);
		long ptrdata=get_address_value(get_address(type_base_addr, offset+pointer_size), pointer_size);
		int hash=(int)get_address_value(get_address(type_base_addr, offset+pointer_size*2), 4);
		int tflag=(int)get_address_value(get_address(type_base_addr, offset+pointer_size*2+4), 1);
		int align=(int)get_address_value(get_address(type_base_addr, offset+pointer_size*2+4+1), 1);
		int field_align=(int)get_address_value(get_address(type_base_addr, offset+pointer_size*2+4+1*2), 1);
		int kind=(int)get_address_value(get_address(type_base_addr, offset+pointer_size*2+4+1*3), 1)&0x1f;
		long equal=get_address_value(get_address(type_base_addr, offset+pointer_size*2+4+1*4), pointer_size);
		long gcdata=get_address_value(get_address(type_base_addr, offset+pointer_size*3+4+1*4), pointer_size);
		int name_off=(int)get_address_value(get_address(type_base_addr, offset+pointer_size*4+4+1*4), 4);
		long ptr_to_this_off=get_address_value(get_address(type_base_addr, offset+pointer_size*4+4*2+1*4), 4);
		String name=get_type_string(get_address(type_base_addr, name_off), tflag);
		if(kind>=Kind.MaxKind.ordinal()) {
			kind=0;
		}
		BasicTypeInfo basic_info=new BasicTypeInfo(get_address(type_base_addr, offset), offset, size, ptrdata, hash, tflag, align, field_align, Kind.values()[kind], equal, gcdata, name);
		basic_type_info_map.put(offset, basic_info);
		name_to_type_map.put(name, offset);

		create_label(get_address(type_base_addr, offset), String.format("datatype.%s.%s", Kind.values()[kind].name(), name));
		try {
			program.getListing().createData(get_address(type_base_addr, offset), get_datatype_by_name("_type"));
			program.getListing().setComment(get_address(type_base_addr, offset+pointer_size*2+4+1*3), ghidra.program.model.listing.CodeUnit.EOL_COMMENT, Kind.values()[kind].name());
			program.getListing().setComment(get_address(type_base_addr, offset+pointer_size*4+4+1*4), ghidra.program.model.listing.CodeUnit.EOL_COMMENT, name);
			if(ptr_to_this_off!=0) {
				program.getListing().setComment(get_address(type_base_addr, offset+pointer_size*4+4*2+1*4), ghidra.program.model.listing.CodeUnit.EOL_COMMENT,
						String.format("%x", type_base_addr.getOffset()+ptr_to_this_off));
			}
		} catch (CodeUnitInsertionException | DataTypeConflictException e) {
			append_message(String.format("Failed to create data: %x %s", get_address(type_base_addr, offset).getOffset(), name));
		}

		Address ext_base_addr=get_address(type_base_addr, offset+pointer_size*4+16);
		if(kind==Kind.Bool.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new BooleanDataType()));
		}else if(kind==Kind.Int.ordinal()) {
			if(pointer_size==8) {
				basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new LongLongDataType()));
			}else {
				basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new IntegerDataType()));
			}
		}else if(kind==Kind.Int8.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new SignedByteDataType()));
		}else if(kind==Kind.Int16.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new ShortDataType()));
		}else if(kind==Kind.Int32.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new IntegerDataType()));
		}else if(kind==Kind.Int64.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new LongLongDataType()));
		}else if(kind==Kind.Uint.ordinal()) {
			if(pointer_size==8) {
				basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new UnsignedLongLongDataType()));
			}else {
				basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new UnsignedIntegerDataType()));
			}
		}else if(kind==Kind.Uint8.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new ByteDataType()));
		}else if(kind==Kind.Uint16.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new UnsignedShortDataType()));
		}else if(kind==Kind.Uint32.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new UnsignedIntegerDataType()));
		}else if(kind==Kind.Uint64.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new UnsignedLongLongDataType()));
		}else if(kind==Kind.Uintptr.ordinal()) {
			if(pointer_size==8) {
				basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new UnsignedLongLongDataType()));
			}else {
				basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new UnsignedIntegerDataType()));
			}
		}else if(kind==Kind.Float32.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new Float4DataType()));
		}else if(kind==Kind.Float64.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new Float8DataType()));
		}else if(kind==Kind.Complex64.ordinal()) {
			StructureDataType complex64_datatype=new StructureDataType("complex64", 0);
			complex64_datatype.setMinimumAlignment(align);
			complex64_datatype.add(new Float4DataType(), "re", null);
			complex64_datatype.add(new Float4DataType(), "im", null);
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, complex64_datatype));
		}else if(kind==Kind.Complex128.ordinal()) {
			StructureDataType complex128_datatype=new StructureDataType("complex128", 0);
			complex128_datatype.setMinimumAlignment(align);
			complex128_datatype.add(new Float8DataType(), "re", null);
			complex128_datatype.add(new Float8DataType(), "im", null);
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, complex128_datatype));
		}else if(kind==Kind.Array.ordinal()) {
			long elem_addr_value=get_address_value(ext_base_addr, pointer_size);
			long slice=get_address_value(get_address(ext_base_addr, pointer_size), pointer_size);
			long len=get_address_value(get_address(ext_base_addr, pointer_size*2), pointer_size);
			if(elem_addr_value!=0) {
				analyze_type(type_base_addr, elem_addr_value-type_base_addr.getOffset());
			}
			basic_type_info_map.replace(offset, new ArrayTypeInfo(basic_info, elem_addr_value-type_base_addr.getOffset(), slice, len));
		}else if(kind==Kind.Chan.ordinal()) {
			long elem_addr_value=get_address_value(ext_base_addr, pointer_size);
			long dir=get_address_value(get_address(ext_base_addr, pointer_size), pointer_size);
			if(elem_addr_value!=0) {
				analyze_type(type_base_addr, elem_addr_value-type_base_addr.getOffset());
			}
			basic_type_info_map.replace(offset, new ChanTypeInfo(basic_info, elem_addr_value-type_base_addr.getOffset(), dir));
		}else if(kind==Kind.Func.ordinal()) {
			int in_len=(short)get_address_value(ext_base_addr, 2);
			int out_len=(short)get_address_value(get_address(ext_base_addr, 2), 2);
			out_len=(short)(out_len&0x1f);
			List<Long> in_type_offset_list = new ArrayList<Long>();
			List<Long> out_type_offset_list = new ArrayList<Long>();
			for(int i=0;i<in_len;i++) {
				long in_type_addr_value=get_address_value(get_address(ext_base_addr, pointer_size+i*pointer_size), pointer_size);
				if(in_type_addr_value!=0) {
					analyze_type(type_base_addr, in_type_addr_value-type_base_addr.getOffset());
				}
				in_type_offset_list.add(in_type_addr_value-type_base_addr.getOffset());
			}
			for(int i=0;i<out_len;i++) {
				long out_type_addr_value=get_address_value(get_address(ext_base_addr, pointer_size+in_len*pointer_size+i*pointer_size), pointer_size);
				if(out_type_addr_value>type_base_addr.getOffset()) {
					analyze_type(type_base_addr, out_type_addr_value-type_base_addr.getOffset());
				}
				out_type_offset_list.add(out_type_addr_value-type_base_addr.getOffset());
			}
			basic_type_info_map.replace(offset, new FuncTypeInfo(basic_info, in_type_offset_list, out_type_offset_list));
		}else if(kind==Kind.Interface.ordinal()) {
			long pkg_path_addr_value=get_address_value(ext_base_addr, pointer_size);
			long methods_addr_value=get_address_value(get_address(ext_base_addr, pointer_size), pointer_size);
			long methods_len=get_address_value(get_address(ext_base_addr, pointer_size*2), pointer_size);

			String pkg_name="";
			if(pkg_path_addr_value!=0) {
				pkg_name=get_type_string(get_address(type_base_addr, pkg_path_addr_value-type_base_addr.getOffset()), 0);
			}
			List<String> method_name_list = new ArrayList<String>();
			List<Long> method_type_offset_list = new ArrayList<Long>();
			for(int i=0;i<methods_len;i++) {
				long method_name_addr_value=get_address_value(get_address(type_base_addr, methods_addr_value+i*2*4-type_base_addr.getOffset()), 4);
				long method_type_offset=get_address_value(get_address(type_base_addr, methods_addr_value+i*2*4-type_base_addr.getOffset()+4), 4);

				String method_name="";
				if(method_name_addr_value!=0) {
					method_name=get_type_string(get_address(type_base_addr, method_name_addr_value), 0);
				}
				if(method_type_offset!=0)
				{
					analyze_type(type_base_addr, method_type_offset);
				}
				method_name_list.add(method_name);
				method_type_offset_list.add(method_type_offset);
			}
			basic_type_info_map.replace(offset, new InterfaceTypeInfo(basic_info, pkg_name, method_name_list, method_type_offset_list));
		}else if(kind==Kind.Map.ordinal()) {
			long key_addr_value=get_address_value(ext_base_addr, pointer_size);
			long elem_addr_value=get_address_value(get_address(ext_base_addr, pointer_size), pointer_size);
			// ...
			if(key_addr_value!=0) {
				analyze_type(type_base_addr, key_addr_value-type_base_addr.getOffset());
			}
			if(elem_addr_value!=0) {
				analyze_type(type_base_addr, elem_addr_value-type_base_addr.getOffset());
			}
			basic_type_info_map.replace(offset, new MapTypeInfo(basic_info, key_addr_value-type_base_addr.getOffset(), elem_addr_value));
		}else if(kind==Kind.Ptr.ordinal()) {
			long elem_addr_value=get_address_value(ext_base_addr, pointer_size);
			analyze_type(type_base_addr, elem_addr_value-type_base_addr.getOffset());
			basic_type_info_map.replace(offset, new PtrTypeInfo(basic_info, elem_addr_value-type_base_addr.getOffset()));
		}else if(kind==Kind.Slice.ordinal()) {
			long elem_addr_value=get_address_value(ext_base_addr, pointer_size);
			if(elem_addr_value!=0) {
				analyze_type(type_base_addr, elem_addr_value-type_base_addr.getOffset());
			}
			basic_type_info_map.replace(offset, new SliceTypeInfo(basic_info, elem_addr_value-type_base_addr.getOffset()));
		}else if(kind==Kind.String.ordinal()) {
			StructureDataType string_datatype=new StructureDataType("string", 0);
			string_datatype.setMinimumAlignment(align);
			string_datatype.add(new PointerDataType(new StringDataType(), pointer_size), "__data", null);
			string_datatype.add(new IntegerDataType(), "__length", null);
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, string_datatype));
		}else if(kind==Kind.Struct.ordinal()) {
			long pkg_path_addr_value=get_address_value(ext_base_addr, pointer_size);
			long fields_addr_value=get_address_value(get_address(ext_base_addr, pointer_size), pointer_size);
			long field_len=get_address_value(get_address(ext_base_addr, pointer_size*2), pointer_size);

			String pkg_name_string="";
			if(pkg_path_addr_value!=0) {
				pkg_name_string=get_type_string(get_address(type_base_addr, pkg_path_addr_value-type_base_addr.getOffset()), 0);
			}
			List<String> field_name_list = new ArrayList<String>();
			List<Long> field_type_offset_list = new ArrayList<Long>();
			for(int i=0;i<field_len;i++) {
				long field_name_addr_value=get_address_value(get_address(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset()), pointer_size);
				long field_type_addr_value=get_address_value(get_address(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset()+pointer_size), pointer_size);
				long offset_embed=get_address_value(get_address(type_base_addr, fields_addr_value+i*3*pointer_size-type_base_addr.getOffset()+pointer_size*2), pointer_size);

				String field_name=get_type_string(get_address(type_base_addr, field_name_addr_value-type_base_addr.getOffset()), 0);
				analyze_type(type_base_addr, field_type_addr_value-type_base_addr.getOffset());
				field_name_list.add(field_name);
				field_type_offset_list.add(field_type_addr_value-type_base_addr.getOffset());
			}
			basic_type_info_map.replace(offset, new StructTypeInfo(basic_info, pkg_name_string, field_align, field_name_list, field_type_offset_list));
		}else if(kind==Kind.UnsafePointer.ordinal()) {
			basic_type_info_map.replace(offset, new OtherTypeInfo(basic_info, new PointerDataType()));
		}else {
			name_to_type_map.remove(name);
		}
		if(ptr_to_this_off!=0) {
			analyze_type(type_base_addr, ptr_to_this_off);
		}
		return true;
	}
}
