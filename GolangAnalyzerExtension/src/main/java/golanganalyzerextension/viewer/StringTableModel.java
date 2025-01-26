package golanganalyzerextension.viewer;

import java.util.List;
import java.util.Map;

import docking.widgets.table.TableColumnDescriptor;
import ghidra.docking.settings.Settings;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.ServiceProvider;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSet;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;
import ghidra.util.datastruct.Accumulator;
import ghidra.util.exception.CancelledException;
import ghidra.util.table.AddressBasedTableModel;
import ghidra.util.table.field.AbstractProgramBasedDynamicTableColumn;
import ghidra.util.table.field.AddressBasedLocation;
import ghidra.util.task.TaskMonitor;
import golanganalyzerextension.service.GolangAnalyzerExtensionPlugin;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;
import golanganalyzerextension.string.GolangString;

class StringTableModel extends AddressBasedTableModel<GolangString> {
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
	public ProgramSelection getProgramSelection(int[] rows) {

		AddressSet address_set = new AddressSet();
		for (int row : rows) {
			GolangString string = getRowObject(row);
			Address addr = string.get_addr();
			if (addr != null) {
				address_set.addRange(addr, addr);
			}
		}
		return new ProgramSelection(address_set);
	}

	@Override
	public Address getAddress(int row) {
		GolangString string = getRowObject(row);
		return string.get_addr();
	}

	@Override
	protected void doLoad(Accumulator<GolangString> accumulator, TaskMonitor monitor)
			throws CancelledException {
		Map<Long, GolangString> string_map=null;
		GolangAnalyzerExtensionService service=plugin_tool.getService(GolangAnalyzerExtensionService.class);
		string_map=service.get_string_map();
		if(string_map==null) {
			return;
		}
		for(GolangString string : string_map.values()) {
			accumulator.add(string);
		}
	}

	@Override
	protected TableColumnDescriptor<GolangString> createTableColumnDescriptor() {
		TableColumnDescriptor<GolangString> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new AddressTableColumn());
		descriptor.addVisibleColumn(new StringTableColumn());

		return descriptor;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	private static class AddressTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangString, AddressBasedLocation> {
		@Override
		public String getColumnName() {
			return "Location";
		}

		@Override
		public AddressBasedLocation getValue(GolangString rowObject, Settings settings, Program pgm,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return new AddressBasedLocation(pgm, rowObject.get_addr());
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	private static class StringTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangString, String> {
		@Override
		public String getColumnName() {
			return "String";
		}

		@Override
		public String getValue(GolangString rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {
			return "\"" + rowObject.get_str() + "\"";
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}
	}
}
