package golanganalyzerextension.service;

import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import db.DBHandle;
import db.DBRecord;
import db.IllegalFieldAccessException;
import db.Schema;
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
import golanganalyzerextension.datatype.GolangDatatype;
import golanganalyzerextension.function.GolangFunction;
import golanganalyzerextension.gobinary.GolangBinary;
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

	// TODO: Fix
	private GolangAnalyzerExtensionProvider gae_provider;

	private GolangBinary go_bin;
	private List<GolangFunction> func_list;
	private List<String> filename_list;
	private Map<Long, GolangDatatype> datatype_map;
	private Map<Long, GolangString> string_map;

	public GolangAnalyzerExtensionPlugin(PluginTool tool) {
		super(tool, true, false);

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

	private Table create_table(String name, Schema schema) {
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

		Table table=create_table(GOLANG_BINARY_TABLE_NAME, GolangBinary.SCHEMA);
		try {
			table.putRecord(bin.get_record());
		} catch (IOException | IllegalFieldAccessException e) {
		}
	}

	@Override
	public List<GolangFunction> get_function_list() {
		return func_list;
	}

	@Override
	public void store_function_list(List<GolangFunction> list) {
		func_list=list;
	}

	@Override
	public List<String> get_filename_list() {
		return filename_list;
	}

	@Override
	public void store_filename_list(List<String> list) {
		filename_list=list;
	}

	@Override
	public void add_filename(String filename) {
		if(filename_list.contains(filename)) {
			return;
		}
		filename_list.add(filename);
	}

	@Override
	public Map<Long, GolangDatatype> get_datatype_map() {
		return datatype_map;
	}

	@Override
	public void store_datatype_map(Map<Long, GolangDatatype> map) {
		datatype_map=map;
	}

	@Override
	public Map<Long, GolangString> get_string_map() {
		return string_map;
	}

	@Override
	public void store_string_map(Map<Long, GolangString> map) {
		string_map=map;
	}
}
