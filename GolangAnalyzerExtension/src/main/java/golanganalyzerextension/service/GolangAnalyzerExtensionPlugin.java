package golanganalyzerextension.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import db.BooleanField;
import db.DBHandle;
import db.DBLongIterator;
import db.DBRecord;
import db.Field;
import db.IllegalFieldAccessException;
import db.LongField;
import db.Schema;
import db.StringField;
import db.Table;
import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.database.ProgramDB;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import golanganalyzerextension.GolangAnalyzerExtensionAnalyzer;
import golanganalyzerextension.datatype.GolangDatatype;
import golanganalyzerextension.datatype.GolangDatatypeRecord;
import golanganalyzerextension.function.GolangFunction;
import golanganalyzerextension.function.GolangFunctionRecord;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;
import golanganalyzerextension.string.GolangString;
import golanganalyzerextension.viewer.GolangAnalyzerExtensionProvider;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "GolangAnalyzerExtension",
	description = "Displays GolangAnalyzerExtension analysis results",
	servicesProvided = { GolangAnalyzerExtensionService.class },
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class GolangAnalyzerExtensionPlugin extends ProgramPlugin implements GolangAnalyzerExtensionService {

	private static final String GOLANG_BINARY_TABLE_NAME="GAE_GolangBinary";
	private static final String GOLANG_FUNCTION_TABLE_NAME="GAE_GolangFunction";
	private static final String GOLANG_FILENAME_TABLE_NAME="GAE_GolangFilename";
	private static final String GOLANG_DATATYPE_TABLE_NAME="GAE_GolangDatatype";
	private static final String GOLANG_STRING_TABLE_NAME="GAE_GolangString";

	private GolangAnalyzerExtensionProvider gae_provider;

	private GolangBinary go_bin;
	private List<GolangFunctionRecord> func_list;
	private List<String> filename_list;
	private Map<Long, GolangDatatypeRecord> datatype_map;
	private Map<Long, GolangString> string_map;

	public GolangAnalyzerExtensionPlugin(PluginTool tool) {
		super(tool);

		go_bin=null;
		func_list=new ArrayList<>();
		filename_list=new ArrayList<>();
		datatype_map=new HashMap<>();
		string_map=new HashMap<>();
	}

	@Override
	protected void init() {
		super.init();
		create_GolangAnalyzerExtension_provider();
	}

	@Override
	public void dispose() {
		gae_provider.closeComponent();
		gae_provider.dispose();

		super.dispose();
	}

	@Override
	protected void programActivated(Program program) {
		gae_provider.setProgram(program);
	}

	private void create_GolangAnalyzerExtension_provider() {
		gae_provider = new GolangAnalyzerExtensionProvider(this);
		gae_provider.setProgram(currentProgram);
		gae_provider.setVisible(true);
	}

	private Table get_table(String name) {
		if(currentProgram==null) {
			return null;
		}
		ProgramDB program_db=(ProgramDB)currentProgram;
		DBHandle db_handle=program_db.getDBHandle();
		return db_handle.getTable(name);
	}

	private Table create_or_open_table(String name, Schema schema) {
		if(currentProgram==null) {
			return null;
		}
		ProgramDB program_db=(ProgramDB)currentProgram;
		DBHandle db_handle=program_db.getDBHandle();
		try {
			Table table=db_handle.getTable(name);
			if(table==null) {
				table=db_handle.createTable(name, schema);
			}
			return table;
		} catch (IOException e) {
			Logger.append_message(String.format("Failed to create table: name=%s, message=%s", name, e.getMessage()));
		}
		return null;
	}

	private Table create_new_table(String name, Schema schema) {
		if(currentProgram==null) {
			return null;
		}
		ProgramDB program_db=(ProgramDB)currentProgram;
		DBHandle db_handle=program_db.getDBHandle();
		try {
			Table table=db_handle.getTable(name);
			if(table==null) {
				table=db_handle.createTable(name, schema);
			} else {
				db_handle.deleteTable(name);
				table=db_handle.createTable(name, schema);
			}
			return table;
		} catch (IOException e) {
			Logger.append_message(String.format("Failed to create table: name=%s, message=%s", name, e.getMessage()));
		}
		return null;
	}

	@Override
	public GolangBinary get_binary() {
		if(go_bin!=null) {
			return go_bin;
		}

		Table table=get_table(GOLANG_BINARY_TABLE_NAME);
		if(table==null) {
			return null;
		}
		try {
			if(!table.hasRecord(GolangBinary.RECORD_KEY)) {
				return null;
			}
			DBRecord record=table.getRecord(GolangBinary.RECORD_KEY);
			go_bin=new GolangBinary(currentProgram, TaskMonitor.DUMMY, record);
		} catch (IOException | IllegalArgumentException e) {
			return null;
		}
		return go_bin;
	}

	@Override
	public void store_binary(GolangBinary bin) {
		go_bin=bin;

		Table table=create_new_table(GOLANG_BINARY_TABLE_NAME, GolangBinary.SCHEMA_V1);
		if(table==null) {
			return;
		}
		try {
			table.putRecord(bin.get_record());
		} catch (IOException | IllegalFieldAccessException e) {
		}
	}

	@Override
	public List<GolangFunctionRecord> get_function_list() {
		if(func_list.size()>0) {
			return func_list;
		}

		Table table=get_table(GOLANG_FUNCTION_TABLE_NAME);
		if(table==null) {
			return func_list;
		}
		List<GolangFunctionRecord> tmp_func_list=new ArrayList<>();
		try {
			DBLongIterator iter=table.longKeyIterator();
			GolangBinary go_bin=get_binary();
			if (go_bin==null) {
				return func_list;
			}
			while(iter.hasNext()) {
				tmp_func_list.add(new GolangFunctionRecord(go_bin, table.getRecord(iter.next())));
			}
		} catch (IOException | IllegalArgumentException e) {
			Logger.append_message(String.format("Failed to get GolangFunction from table: message=%s", e.getMessage()));;
		}
		func_list=tmp_func_list;
		return func_list;
	}

	@Override
	public void store_function_list(List<GolangFunction> list) {
		List<GolangFunctionRecord> tmp_func_list=new ArrayList<>();
		for(GolangFunction go_func : list) {
			GolangFunctionRecord record=new GolangFunctionRecord(go_func);
			tmp_func_list.add(record);
		}
		func_list=tmp_func_list;

		save_function_list(func_list);
	}

	@Override
	public void add_function(GolangFunction func) {
		func_list.add(new GolangFunctionRecord(func));
		save_function_list(func_list);
	}

	@Override
	public void add_function(GolangFunctionRecord func) {
		func_list.add(func);
		save_function_list(func_list);
	}

	private void save_function_list(List<GolangFunctionRecord> list) {
		Table table=create_new_table(GOLANG_FUNCTION_TABLE_NAME, GolangFunctionRecord.SCHEMA_V1);
		if(table==null) {
			return;
		}
		for(GolangFunctionRecord record : list) {
			try {
				table.putRecord(record.get_record());
			} catch (IOException | IllegalFieldAccessException e) {
				Logger.append_message(String.format("Failed to put GolangFunction to table: message=%s", e.getMessage()));;
			}
		}
	}

	private static final int RECORD_FILENAME_INDEX_V0=0;
	public static final Schema GOLANG_FILENAME_SCHEMA_V0=new Schema(0, "GolangFilename",
			new Field[] {
					StringField.INSTANCE,
					},
			new String[] {
					"Filename",
					}
	);
	private static final int RECORD_GAE_VERSION_INDEX_V1=0;
	private static final int RECORD_FILENAME_INDEX_V1=1;
	public static final Schema GOLANG_FILENAME_SCHEMA_V1=new Schema(1, "GolangFilename",
			new Field[] {
					StringField.INSTANCE,
					StringField.INSTANCE,
					},
			new String[] {
					"GAEVersion",
					"Filename",
					}
	);
	@Override
	public List<String> get_filename_list() {
		if(filename_list.size()>0) {
			return filename_list;
		}

		Table table=get_table(GOLANG_FILENAME_TABLE_NAME);
		if(table==null) {
			return filename_list;
		}
		List<String> tmp_filename_list=filename_list=new ArrayList<>();
		try {
			DBLongIterator iter=table.longKeyIterator();
			while(iter.hasNext()) {
				try {
					DBRecord record=table.getRecord(iter.next());
					if (record.hasSameSchema(GOLANG_FILENAME_SCHEMA_V0)) {
						tmp_filename_list.add(record.getString(RECORD_FILENAME_INDEX_V0));
					} else if (record.hasSameSchema(GOLANG_FILENAME_SCHEMA_V1)) {
						tmp_filename_list.add(record.getString(RECORD_FILENAME_INDEX_V1));
					} else {
						throw new IllegalArgumentException("Invalid DBRecord schema");
					}
				} catch(IllegalArgumentException e) {
					Logger.append_message(String.format("Failed to get GolangFilename from table: message=%s", e.getMessage()));;
				}
			}
		} catch(IOException e) {
			Logger.append_message(String.format("Failed to get GolangFilename from table: message=%s", e.getMessage()));;
		}
		tmp_filename_list=filename_list;
		return filename_list;
	}

	@Override
	public void store_filename_list(List<String> list) {
		Table table=create_new_table(GOLANG_FILENAME_TABLE_NAME, GOLANG_FILENAME_SCHEMA_V1);
		if(table==null) {
			return;
		}
		for(int i=0; i<list.size(); i++) {
			try {
				DBRecord record=GOLANG_FILENAME_SCHEMA_V1.createRecord(i);
				record.setString(RECORD_GAE_VERSION_INDEX_V1, GolangAnalyzerExtensionAnalyzer.VERSION);
				record.setString(RECORD_FILENAME_INDEX_V1, list.get(i));
				table.putRecord(record);
			} catch (IOException | IllegalFieldAccessException e) {
				Logger.append_message(String.format("Failed to put GolangFilename to table: message=%s", e.getMessage()));;
			}
		}
		filename_list=list;
	}

	@Override
	public void add_filename(String filename) {
		if(filename_list.contains(filename)) {
			return;
		}
		filename_list.add(filename);
		Table table=create_or_open_table(GOLANG_FILENAME_TABLE_NAME, GOLANG_FILENAME_SCHEMA_V1);
		if(table==null) {
			return;
		}
		int idx=filename_list.size();
		try {
			DBRecord record=GOLANG_FILENAME_SCHEMA_V1.createRecord(idx);
			record.setString(RECORD_GAE_VERSION_INDEX_V1, GolangAnalyzerExtensionAnalyzer.VERSION);
			record.setString(RECORD_FILENAME_INDEX_V1, filename);
			table.putRecord(record);
		} catch (IOException | IllegalFieldAccessException e) {
			Logger.append_message(String.format("Failed to put a GolangFilename to table: message=%s", e.getMessage()));;
		}
	}

	@Override
	public Map<Long, GolangDatatypeRecord> get_datatype_map() {
		if(datatype_map.size()>0) {
			return datatype_map;
		}

		Table table=get_table(GOLANG_DATATYPE_TABLE_NAME);
		if(table==null) {
			return datatype_map;
		}
		Map<Long, GolangDatatypeRecord> tmp_datatype_map=new HashMap<>();
		try {
			DBLongIterator iter=table.longKeyIterator();
			while(iter.hasNext()) {
				try {
					GolangBinary go_bin=get_binary();
					if (go_bin==null) {
						return datatype_map;
					}
					GolangDatatypeRecord record=new GolangDatatypeRecord(go_bin, table.getRecord(iter.next()));
					tmp_datatype_map.put(record.get_type_offset(), record);
				} catch (IllegalArgumentException e) {
					Logger.append_message(String.format("Failed to get GolangDatatype from table: message=%s", e.getMessage()));;
				}
			}
		} catch (IOException e) {
			Logger.append_message(String.format("Failed to get GolangDatatype from table: message=%s", e.getMessage()));;
		}
		datatype_map=tmp_datatype_map;
		return datatype_map;
	}

	@Override
	public void store_datatype_map(Map<Long, GolangDatatype> map) {
		Map<Long, GolangDatatypeRecord> tmp_datatype_map=new HashMap<>();

		Table table=create_new_table(GOLANG_DATATYPE_TABLE_NAME, GolangDatatypeRecord.SCHEMA_V1);
		if(table==null) {
			return;
		}
		for(GolangDatatype go_datatype : map.values()) {
			GolangDatatypeRecord record=new GolangDatatypeRecord(go_datatype);
			tmp_datatype_map.put(record.get_type_offset(), record);
			try {
				table.putRecord(record.get_record());
			} catch (IOException | IllegalFieldAccessException e) {
				Logger.append_message(String.format("Failed to put GolangDatatype to table: message=%s", e.getMessage()));;
			}
		}
		datatype_map=tmp_datatype_map;
	}

	private static final int RECORD_ADDR_INDEX_V1=1;
	private static final int RECORD_STRING_INDEX_V1=2;
	private static final int RECORD_IS_STRUCT_INDEX_V1=3;
	private static final Schema GOLANG_STRING_SCHEMA_V1=new Schema(1, "GolangString",
			new Field[] {
					StringField.INSTANCE,
					LongField.INSTANCE,
					StringField.INSTANCE,
					BooleanField.INSTANCE,
					},
			new String[] {
					"GAEVersion",
					"Addr",
					"String",
					"IsStruct"
					}
	);
	@Override
	public Map<Long, GolangString> get_string_map() {
		if(string_map.size()>0) {
			return string_map;
		}

		Table table=get_table(GOLANG_STRING_TABLE_NAME);
		if(table==null) {
			return string_map;
		}
		GolangBinary go_bin=get_binary();
		if(go_bin==null) {
			return string_map;
		}
		Map<Long, GolangString> tmp_string_map=new HashMap<>();
		try {
			DBLongIterator iter=table.longKeyIterator();
			while(iter.hasNext()) {
				try {
					long key;
					long addr_value;
					String str;
					boolean is_struct;
					DBRecord record=table.getRecord(iter.next());
					if (record.hasSameSchema(GOLANG_STRING_SCHEMA_V1)) {
						key=record.getKey();
						addr_value=record.getLongValue(RECORD_ADDR_INDEX_V1);
						str=record.getString(RECORD_STRING_INDEX_V1);
						is_struct=record.getBooleanValue(RECORD_IS_STRUCT_INDEX_V1);
					} else {
						throw new IllegalArgumentException("Invalid DBRecord schema");
					}
					tmp_string_map.put(key, new GolangString(is_struct, go_bin.get_address(addr_value), str));
				} catch (IllegalArgumentException | BinaryAccessException e) {
					Logger.append_message(String.format("Failed to get GolangString from table: message=%s", e.getMessage()));;
				}
			}
		} catch (IOException e) {
			Logger.append_message(String.format("Failed to get GolangString from table: message=%s", e.getMessage()));;
		}
		string_map=tmp_string_map;
		return string_map;
	}

	@Override
	public void store_string_map(Map<Long, GolangString> map) {
		Table table=create_new_table(GOLANG_STRING_TABLE_NAME, GOLANG_STRING_SCHEMA_V1);
		if(table==null) {
			return;
		}
		for(Map.Entry<Long, GolangString> entry : map.entrySet()) {
			try {
				DBRecord record=GOLANG_STRING_SCHEMA_V1.createRecord(entry.getKey());
				GolangString go_str=entry.getValue();
				record.setString(RECORD_GAE_VERSION_INDEX_V1, GolangAnalyzerExtensionAnalyzer.VERSION);
				record.setLongValue(RECORD_ADDR_INDEX_V1, go_str.get_addr().getOffset());
				record.setString(RECORD_STRING_INDEX_V1, go_str.get_str());
				record.setBooleanValue(RECORD_IS_STRUCT_INDEX_V1, go_str.get_is_struct());
				table.putRecord(record);
			} catch (IOException | IllegalFieldAccessException e) {
				Logger.append_message(String.format("Failed to put GolangString to table: message=%s", e.getMessage()));;
			}
		}
		string_map=map;
	}
}
