package golanganalyzerextension.viewer;

import java.util.List;
import java.util.Map;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.task.TaskMonitor;
import golanganalyzerextension.service.GolangAnalyzerExtensionPlugin;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;
import golanganalyzerextension.string.GolangString;

class StringTableModel extends AddressBasedTableModel<String> {
	private PluginTool plugin_tool;

	StringTableModel(PluginTool tool, Program program, TaskMonitor monitor, GolangAnalyzerExtensionPlugin gae_plugin) {
		super("Functions Table", tool, program, monitor, true);

		plugin_tool=tool;
	}

	void update_table(Program new_program) {
		setProgram(new_program);
		reload();
	}

	@Override
	public Address getAddress(int row) {
		return null;
	}

	@Override
	protected void doLoad(Accumulator<String> accumulator, TaskMonitor monitor)
			throws CancelledException {
		Map<Long, GolangString> string_map=null;
		GolangAnalyzerExtensionService service=plugin_tool.getService(GolangAnalyzerExtensionService.class);
		string_map=service.get_string_map();
		if(string_map==null) {
			return;
		}
		for(GolangString string : string_map.values()) {
			accumulator.add(string.get_str());
		}
	}

	@Override
	protected TableColumnDescriptor<String> createTableColumnDescriptor() {
		TableColumnDescriptor<String> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new StringTableColumn());

		return descriptor;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class StringTableColumn
			extends AbstractProgramBasedDynamicTableColumn<String, String> {
		@Override
		public String getColumnName() {
			return "String";
		}

		@Override
		public String getValue(String rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}
	}
}
