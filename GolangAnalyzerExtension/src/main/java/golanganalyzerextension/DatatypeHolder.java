package golanganalyzerextension;

import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.data.BooleanDataType;
import ghidra.program.model.data.ByteDataType;
import ghidra.program.model.data.DataType;
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
import golanganalyzerextension.datatype.GolangDatatype;
import golanganalyzerextension.gobinary.GolangBinary;

public class DatatypeHolder {
	private Map<Long, GolangDatatype> datatype_map;
	private Map<String, DataType> hardcode_datatype_map;
	private GolangBinary go_bin;
	private boolean is_go16;

	DatatypeHolder(GolangBinary go_bin, boolean is_go16) {
		this.datatype_map=new HashMap<Long, GolangDatatype>();;

		this.go_bin=go_bin;
		this.is_go16=is_go16;

		init_hardcode_golang_datatype();
	}

	public Map<Long, GolangDatatype> get_datatype_map() {
		return datatype_map;
	}

	public Set<Long> get_key_set() {
		return datatype_map.keySet();
	}

	public boolean contain_key(long key) {
		return datatype_map.containsKey(key);
	}

	public GolangDatatype get_go_datatype_by_key(long key) {
		return datatype_map.get(key);
	}

	public DataType get_datatype_by_key(long key) {
		GolangDatatype result = datatype_map.get(key);
		if(result!=null) {
			return result.get_inner_datatype(false);
		}
		return null;
	}

	public DataType get_datatype_by_name(String name) {
		for(Map.Entry<Long, GolangDatatype> entry : datatype_map.entrySet()) {
			GolangDatatype tmp_go_datatype=entry.getValue();
			if(!tmp_go_datatype.get_name().equals(name)) {
				continue;
			}
			DataType tmp_datatype=tmp_go_datatype.get_inner_datatype(false);
			if(tmp_datatype.getLength()>0) {
				return tmp_datatype;
			}
		}

		return hardcode_datatype_map.get(name);
	}

	void put_datatype(long key, GolangDatatype go_datatype) {
		datatype_map.put(key, go_datatype);
	}

	void replace_datatype(long key, GolangDatatype go_datatype) {
		datatype_map.replace(key, go_datatype);
	}

	private void init_hardcode_golang_datatype() {
		hardcode_datatype_map=new HashMap<String, DataType>();
		int pointer_size=go_bin.get_pointer_size();

		// runtime/type.go
		StructureDataType _type_datatype=new StructureDataType("runtime._type", 0);
		_type_datatype.setPackingEnabled(true);
		_type_datatype.setExplicitMinimumAlignment(pointer_size);
		_type_datatype.add(new PointerDataType(new VoidDataType(), pointer_size), "size", "");
		_type_datatype.add(new PointerDataType(new VoidDataType(), pointer_size), "ptrdata", "");
		_type_datatype.add(new UnsignedIntegerDataType(), "hash", "");
		_type_datatype.add(new UnsignedCharDataType(), "tflag", "");
		_type_datatype.add(new UnsignedCharDataType(), "align", "");
		_type_datatype.add(new UnsignedCharDataType(), "fieldAlign", "");
		_type_datatype.add(new UnsignedCharDataType(), "kind", "");
		_type_datatype.add(new PointerDataType(new VoidDataType(), pointer_size), "equal", "");
		_type_datatype.add(new PointerDataType(new UnsignedCharDataType(), pointer_size), "gcdata", "");
		if(is_go16) {
			_type_datatype.add(new PointerDataType(new VoidDataType()), "_string", "");
			_type_datatype.add(new PointerDataType(new VoidDataType()), "x", "");
			_type_datatype.add(new PointerDataType(new VoidDataType()), "ptrto", "");
		}else {
			_type_datatype.add(new UnsignedIntegerDataType(), "str", "");
			_type_datatype.add(new UnsignedIntegerDataType(), "ptrToThis", "");
		}
		// zero *byte (ver 1.5)
		hardcode_datatype_map.put("runtime._type", _type_datatype);

		// runtime/chan.go
		StructureDataType waitq_datatype=new StructureDataType("runtime.waitq", 0);
		waitq_datatype.setPackingEnabled(true);
		waitq_datatype.setExplicitMinimumAlignment(pointer_size);
		waitq_datatype.add(new PointerDataType(new VoidDataType(), pointer_size), "first", "");// *sudog in runtime/runtime2.go
		waitq_datatype.add(new PointerDataType(new VoidDataType(), pointer_size), "last", "");// *sudog
		hardcode_datatype_map.put("runtime.waitq", waitq_datatype);

		// runtime/runtime2.go
		StructureDataType mutex_datatype=new StructureDataType("runtime.mutex", 0);
		mutex_datatype.setPackingEnabled(true);
		mutex_datatype.setExplicitMinimumAlignment(pointer_size);
		// lockRankStruct : (ver 1.15)
		mutex_datatype.add(new PointerDataType(new VoidDataType(), pointer_size), "key", "");
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
		hardcode_datatype_map.put("unsafe.Pointer", new PointerDataType(new VoidDataType(), pointer_size));
	}
}
