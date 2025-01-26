package golanganalyzerextension.datatype;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.NoSuchElementException;
import java.util.Optional;

import db.BinaryField;
import db.DBRecord;
import db.Field;
import db.IllegalFieldAccessException;
import db.IntField;
import db.LongField;
import db.Schema;
import db.StringField;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.DataType;
import ghidra.program.model.data.Structure;
import ghidra.program.model.data.StructureDataType;
import golanganalyzerextension.GolangAnalyzerExtensionAnalyzer;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;

public class GolangDatatypeRecord {
	private static final int RECORD_OFFSET_INDEX_V0=0;
	private static final int RECORD_ADDR_INDEX_V0=1;
	private static final int RECORD_NAME_INDEX_V0=2;
	private static final int RECORD_SIZE_INDEX_V0=3;
	private static final int RECORD_KIND_INDEX_V0=4;
	private static final int RECORD_UNCOMMON_INDEX_V0=5;
	private static final int RECORD_CATEGORY_INDEX_V0=6;
	public static final Schema SCHEMA_V0=new Schema(0, "GolangDatatype",
			new Field[] {
					LongField.INSTANCE,
					LongField.INSTANCE,
					StringField.INSTANCE,
					LongField.INSTANCE,
					IntField.INSTANCE,
					BinaryField.INSTANCE,
					StringField.INSTANCE,
					},
			new String[] {
					"Offset",
					"Addr",
					"Name",
					"Size",
					"Kind",
					"Uncommon",
					"Category",
					}
	);
	private static final int RECORD_GAE_VERSION_INDEX_V1=0;
	private static final int RECORD_OFFSET_INDEX_V1=1;
	private static final int RECORD_ADDR_INDEX_V1=2;
	private static final int RECORD_NAME_INDEX_V1=3;
	private static final int RECORD_SIZE_INDEX_V1=4;
	private static final int RECORD_KIND_INDEX_V1=5;
	private static final int RECORD_UNCOMMON_INDEX_V1=6;
	private static final int RECORD_CATEGORY_INDEX_V1=7;
	public static final Schema SCHEMA_V1=new Schema(1, "GolangDatatype",
			new Field[] {
					StringField.INSTANCE,
					LongField.INSTANCE,
					LongField.INSTANCE,
					StringField.INSTANCE,
					LongField.INSTANCE,
					IntField.INSTANCE,
					BinaryField.INSTANCE,
					StringField.INSTANCE,
					},
			new String[] {
					"GAEVersion",
					"Offset",
					"Addr",
					"Name",
					"Size",
					"Kind",
					"Uncommon",
					"Category",
					}
	);

	long type_offset;
	Address addr;
	String name;
	long size;
	Kind kind;
	UncommonType uncommon_type;
	String category_path;
	DataType datatype;

	public GolangDatatypeRecord(GolangDatatype go_datatype) {
		type_offset=go_datatype.get_type_offset();
		addr=go_datatype.get_addr();
		name=go_datatype.get_name();
		size=go_datatype.get_size();
		kind=go_datatype.get_kind();
		uncommon_type=go_datatype.get_uncommon_type().orElse(null);
		category_path=go_datatype.get_category_path();
		datatype=go_datatype.get_datatype();
	}

	public GolangDatatypeRecord(GolangBinary go_bin, DBRecord record) throws IllegalArgumentException {
		try {
			if(record.hasSameSchema(SCHEMA_V0)) {
				type_offset=record.getLongValue(RECORD_OFFSET_INDEX_V0);
				addr=go_bin.get_address(record.getLongValue(RECORD_ADDR_INDEX_V0));
				name=record.getString(RECORD_NAME_INDEX_V0);
				size=record.getLongValue(RECORD_SIZE_INDEX_V0);
				kind=Kind.values()[record.getIntValue(RECORD_KIND_INDEX_V0)];
				uncommon_type=(UncommonType)bytes_to_obj(record.getBinaryData(RECORD_UNCOMMON_INDEX_V0));
				category_path=record.getString(RECORD_CATEGORY_INDEX_V0);
			} else if (record.hasSameSchema(SCHEMA_V1)) {
				type_offset=record.getLongValue(RECORD_OFFSET_INDEX_V1);
				addr=go_bin.get_address(record.getLongValue(RECORD_ADDR_INDEX_V1));
				name=record.getString(RECORD_NAME_INDEX_V1);
				size=record.getLongValue(RECORD_SIZE_INDEX_V1);
				kind=Kind.values()[record.getIntValue(RECORD_KIND_INDEX_V1)];
				uncommon_type=(UncommonType)bytes_to_obj(record.getBinaryData(RECORD_UNCOMMON_INDEX_V1));
				category_path=record.getString(RECORD_CATEGORY_INDEX_V1);
			} else {
				throw new IllegalArgumentException("Invalid DBRecord schema");
			}
			datatype=go_bin.get_datatype(category_path, name).orElseThrow();
		} catch (BinaryAccessException | IllegalFieldAccessException | NoSuchElementException e) {
			throw new IllegalArgumentException(String.format("Invalid DBRecord field: message=%s", e.getMessage()));
		}
	}

	public DBRecord get_record() throws IllegalFieldAccessException {
		DBRecord record=SCHEMA_V1.createRecord(addr.getOffset());
		record.setString(RECORD_GAE_VERSION_INDEX_V1, GolangAnalyzerExtensionAnalyzer.VERSION);
		record.setLongValue(RECORD_OFFSET_INDEX_V1, type_offset);
		record.setLongValue(RECORD_ADDR_INDEX_V1, addr.getOffset());
		record.setString(RECORD_NAME_INDEX_V1, name);
		record.setLongValue(RECORD_SIZE_INDEX_V1, size);
		record.setIntValue(RECORD_KIND_INDEX_V1, kind.ordinal());
		record.setBinaryData(RECORD_UNCOMMON_INDEX_V1, obj_to_bytes(uncommon_type));
		record.setString(RECORD_CATEGORY_INDEX_V1, category_path);
		return record;
	}

	public long get_type_offset() {
		return type_offset;
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

	public DataType get_datatype() {
		return datatype;
	}

	public Structure get_struct() {
		if(datatype instanceof Structure) {
			return (Structure)datatype;
		}
		StructureDataType struct_datatype=new StructureDataType(name, 0);
		if(datatype.getLength()!=0) {
			struct_datatype.add(datatype);
		}
		return struct_datatype;
	}

	private static byte[] obj_to_bytes(Object obj) {
		ByteArrayOutputStream byte_out = new ByteArrayOutputStream();
		ObjectOutputStream out;
		try {
			out = new ObjectOutputStream(byte_out);
			out.writeObject(obj);
			return byte_out.toByteArray();
		} catch (IOException e) {
			Logger.append_message(String.format("Failed to convert obj to bytes: message=%s", e.getMessage()));
		}
		return null;
	}

	private static Object bytes_to_obj(byte[] bytes) {
		ByteArrayInputStream byte_in = new ByteArrayInputStream(bytes);
		ObjectInputStream in;
		try {
			in = new ObjectInputStream(byte_in);
			return in.readObject();
		} catch (IOException | ClassNotFoundException e) {
			Logger.append_message(String.format("Failed to convert bytes to obj: message=%s", e.getMessage()));
		}
		return null;
	}
}
