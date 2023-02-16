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
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;

public class GolangFunctionRecord {

	private static final int RECORD_ADDR_INDEX=0;
	private static final int RECORD_NAME_INDEX=1;
	private static final int RECORD_SIZE_INDEX=2;
	private static final int RECORD_ARG_SIZE_INDEX=3;
	private static final int RECORD_FILE_LINE_INDEX=4;
	private static final int RECORD_FRAME_INDEX=5;
	public static final Schema SCHEMA=new Schema(0, "GolangFunction",
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

	@SuppressWarnings("unchecked")
	public GolangFunctionRecord(GolangBinary go_bin, DBRecord record) throws IllegalArgumentException {
		if(!record.hasSameSchema(SCHEMA)) {
			throw new IllegalArgumentException("Invalid DBRecord schema");
		}

		try {
			func_addr=go_bin.get_address(record.getLongValue(RECORD_ADDR_INDEX));
			func_name=record.getString(RECORD_NAME_INDEX);
			func_size=record.getLongValue(RECORD_SIZE_INDEX);
			arg_size=record.getIntValue(RECORD_ARG_SIZE_INDEX);
			Object file_line_obj=bytes_to_obj(record.getBinaryData(RECORD_FILE_LINE_INDEX));
			if(file_line_obj instanceof Map) {
				file_line_map=(Map<Integer, FileLine>)file_line_obj;
			} else {
				file_line_map=new HashMap<>();
			}
			Object frame_obj=bytes_to_obj(record.getBinaryData(RECORD_FRAME_INDEX));
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
		DBRecord record=SCHEMA.createRecord(func_addr.getOffset());
		record.setLongValue(RECORD_ADDR_INDEX, func_addr.getOffset());
		record.setString(RECORD_NAME_INDEX, func_name);
		record.setLongValue(RECORD_SIZE_INDEX, func_size);
		record.setIntValue(RECORD_ARG_SIZE_INDEX, arg_size);
		byte[] file_line_bytes=obj_to_bytes(file_line_map);
		if(file_line_bytes==null) {
			file_line_bytes=new byte[0];
		}
		record.setBinaryData(RECORD_FILE_LINE_INDEX, file_line_bytes);
		byte[] frame_bytes=obj_to_bytes(frame_map);
		if(frame_bytes==null) {
			frame_bytes=new byte[0];
		}
		record.setBinaryData(RECORD_FRAME_INDEX, frame_bytes);
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
