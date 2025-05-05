package golanganalyzerextension.function;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;

import db.BinaryField;
import db.DBRecord;
import db.Field;
import db.IllegalFieldAccessException;
import db.IntField;
import db.LongField;
import db.Schema;
import db.StringField;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Parameter;
import golanganalyzerextension.GolangAnalyzerExtensionAnalyzer;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;

public class GolangFunctionRecord {

	private static final int RECORD_ADDR_INDEX_V0=0;
	private static final int RECORD_NAME_INDEX_V0=1;
	private static final int RECORD_SIZE_INDEX_V0=2;
	private static final int RECORD_ARG_SIZE_INDEX_V0=3;
	private static final int RECORD_FILE_LINE_INDEX_V0=4;
	private static final int RECORD_FRAME_INDEX_V0=5;
	public static final Schema SCHEMA_V0=new Schema(0, "GolangFunction",
			new Field[] {
					LongField.INSTANCE,
					StringField.INSTANCE,
					LongField.INSTANCE,
					IntField.INSTANCE,
					BinaryField.INSTANCE,
					BinaryField.INSTANCE,
					},
			new String[] {
					"Addr",
					"Name",
					"Size",
					"ArgSize",
					"FileLine",
					"Frame",
					}
	);
	private static final int RECORD_GAE_VERSION_INDEX_V1=0;
	private static final int RECORD_ADDR_INDEX_V1=1;
	private static final int RECORD_NAME_INDEX_V1=2;
	private static final int RECORD_SIZE_INDEX_V1=3;
	private static final int RECORD_ARG_SIZE_INDEX_V1=4;
	private static final int RECORD_FILE_LINE_INDEX_V1=5;
	private static final int RECORD_FRAME_INDEX_V1=6;
	public static final Schema SCHEMA_V1=new Schema(1, "GolangFunction",
			new Field[] {
					StringField.INSTANCE,
					LongField.INSTANCE,
					StringField.INSTANCE,
					LongField.INSTANCE,
					IntField.INSTANCE,
					BinaryField.INSTANCE,
					BinaryField.INSTANCE,
					},
			new String[] {
					"GAEVersion",
					"Addr",
					"Name",
					"Size",
					"ArgSize",
					"FileLine",
					"Frame",
					}
	);

	private Address func_addr;
	private String func_name;
	private long func_size;
	private int arg_size;
	private Map<Integer, FileLine> file_line_map;
	private Map<Integer, Long> frame_map;
	private Parameter[] params;

	public GolangFunctionRecord(GolangFunction go_func) {
		func_addr=go_func.get_func_addr();
		func_name=go_func.get_func_name();
		func_size=go_func.get_func_size();
		arg_size=go_func.get_arg_size();
		file_line_map=go_func.get_file_line_comment_map();
		frame_map=go_func.get_frame_map();
		params=(Parameter[])go_func.get_params().toArray(new Parameter[go_func.get_params().size()]);
	}

	public GolangFunctionRecord(Address func_addr, String func_name, long func_size, int arg_size,
			Map<Integer, FileLine> file_line_map, Map<Integer, Long> frame_map, Parameter[] params) {
		this.func_addr=func_addr;
		this.func_name=func_name;
		this.func_size=func_size;
		this.arg_size=arg_size;
		this.file_line_map=file_line_map;
		this.frame_map=frame_map;
		this.params=params;
	}

	@SuppressWarnings("unchecked")
	public GolangFunctionRecord(GolangBinary go_bin, DBRecord record) throws IllegalArgumentException {

		try {
			Object file_line_obj;
			Object frame_obj;
			if(record.hasSameSchema(SCHEMA_V0)) {
				func_addr=go_bin.get_address(record.getLongValue(RECORD_ADDR_INDEX_V0));
				func_name=record.getString(RECORD_NAME_INDEX_V0);
				func_size=record.getLongValue(RECORD_SIZE_INDEX_V0);
				arg_size=record.getIntValue(RECORD_ARG_SIZE_INDEX_V0);
				file_line_obj=bytes_to_obj(record.getBinaryData(RECORD_FILE_LINE_INDEX_V0));
				frame_obj=bytes_to_obj(record.getBinaryData(RECORD_FRAME_INDEX_V0));
			} else if (record.hasSameSchema(SCHEMA_V1)) {
				func_addr=go_bin.get_address(record.getLongValue(RECORD_ADDR_INDEX_V1));
				func_name=record.getString(RECORD_NAME_INDEX_V1);
				func_size=record.getLongValue(RECORD_SIZE_INDEX_V1);
				arg_size=record.getIntValue(RECORD_ARG_SIZE_INDEX_V1);
				file_line_obj=bytes_to_obj(record.getBinaryData(RECORD_FILE_LINE_INDEX_V1));
				frame_obj=bytes_to_obj(record.getBinaryData(RECORD_FRAME_INDEX_V1));
			} else {
				throw new IllegalArgumentException("Invalid DBRecord schema");
			}

			if(file_line_obj instanceof Map) {
				file_line_map=(Map<Integer, FileLine>)file_line_obj;
			} else {
				file_line_map=new HashMap<>();
			}
			if(frame_obj instanceof Map) {
				frame_map=(Map<Integer, Long>)frame_obj;
			} else {
				frame_map=new HashMap<>();
			}
		} catch(BinaryAccessException | IllegalFieldAccessException | ClassCastException e) {
			throw new IllegalArgumentException(String.format("Invalid DBRecord field: message=%s", e.getMessage()));
		}
		Function func=go_bin.get_function(func_addr).orElse(null);
		if(func==null) {
			params=new Parameter[0];
		} else {
			params=func.getParameters();
		}
	}

	public DBRecord get_record() throws IllegalFieldAccessException {
		DBRecord record=SCHEMA_V1.createRecord(func_addr.getOffset());
		record.setString(RECORD_GAE_VERSION_INDEX_V1, GolangAnalyzerExtensionAnalyzer.VERSION);
		record.setLongValue(RECORD_ADDR_INDEX_V1, func_addr.getOffset());
		record.setString(RECORD_NAME_INDEX_V1, func_name);
		record.setLongValue(RECORD_SIZE_INDEX_V1, func_size);
		record.setIntValue(RECORD_ARG_SIZE_INDEX_V1, arg_size);
		byte[] file_line_bytes=obj_to_bytes(file_line_map);
		if(file_line_bytes==null) {
			file_line_bytes=new byte[0];
		}
		record.setBinaryData(RECORD_FILE_LINE_INDEX_V1, file_line_bytes);
		byte[] frame_bytes=obj_to_bytes(frame_map);
		if(frame_bytes==null) {
			frame_bytes=new byte[0];
		}
		record.setBinaryData(RECORD_FRAME_INDEX_V1, frame_bytes);
		return record;
	}

	public Address get_func_addr() {
		return func_addr;
	}

	public String get_func_name() {
		return func_name;
	}

	public long get_func_size() {
		return func_size;
	}

	public int get_arg_size() {
		return arg_size;
	}

	public Map<Integer, FileLine> get_file_line_comment_map() {
		return file_line_map;
	}

	public Map<Integer, Long> get_frame_map() {
		return frame_map;
	}

	public Parameter[] get_params() {
		return params;
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
