package golanganalyzerextension.viewer;

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
import ghidra.util.task.TaskMonitor;
import golanganalyzerextension.datatype.GolangDatatypeRecord;
import golanganalyzerextension.datatype.Kind;
import golanganalyzerextension.service.GolangAnalyzerExtensionPlugin;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;

public class DatatypeTableModel extends AddressBasedTableModel<GolangDatatypeRecord> {
	private PluginTool plugin_tool;
	// private GolangAnalyzerExtensionPlugin gae_plugin;
	// private DatatypeDetailProvider datatype_detail_provider;

	DatatypeTableModel(PluginTool tool, Program program, TaskMonitor monitor, GolangAnalyzerExtensionPlugin gae_plugin) {
		super("Datatypes Table", tool, program, monitor, true);

		plugin_tool=tool;
		// this.gae_plugin=gae_plugin;
	}

	void update_table(Program new_program) {
		setProgram(new_program);
		reload();
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet address_set = new AddressSet();
		for (int row : rows) {
			GolangDatatypeRecord go_datatype = getRowObject(row);
			Address addr = go_datatype.get_addr();
			if (addr != null) {
				address_set.addRange(addr, addr);
			}
		}
		return new ProgramSelection(address_set);
	}

	@Override
	public Address getAddress(int row) {
		GolangDatatypeRecord go_datatype = getRowObject(row);
		/*datatype_detail_provider=new DatatypeDetailProvider(gae_plugin, go_datatype);
		datatype_detail_provider.getTool().showComponentProvider(datatype_detail_provider, true);
		datatype_detail_provider.toFront();*/
		return go_datatype.get_addr();
	}

	@Override
	protected void doLoad(Accumulator<GolangDatatypeRecord> accumulator, TaskMonitor monitor)
			throws CancelledException {
		Map<Long, GolangDatatypeRecord> datatype_map=null;
		GolangAnalyzerExtensionService service=plugin_tool.getService(GolangAnalyzerExtensionService.class);
		datatype_map=service.get_datatype_map();
		if(datatype_map==null) {
			return;
		}
		for(Map.Entry<Long, GolangDatatypeRecord> entry : datatype_map.entrySet()) {
			accumulator.add(entry.getValue());
		}
	}

	@Override
	protected TableColumnDescriptor<GolangDatatypeRecord> createTableColumnDescriptor() {
		TableColumnDescriptor<GolangDatatypeRecord> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new DatatypeNameTableColumn());
		descriptor.addVisibleColumn(new DatatypeSizeTableColumn());
		descriptor.addVisibleColumn(new DatatypeKindTableColumn());

		return descriptor;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================


	private static class DatatypeNameTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangDatatypeRecord, String> {
		@Override
		public String getColumnName() {
			return "Struct Name";
		}

		@Override
		public String getValue(GolangDatatypeRecord rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.get_name();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	private static class DatatypeSizeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangDatatypeRecord, Integer> {
		@Override
		public String getColumnName() {
			return "Size";
		}

		@Override
		public Integer getValue(GolangDatatypeRecord rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {

			return (int)rowObject.get_size();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	private static class DatatypeKindTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangDatatypeRecord, Kind> {
		@Override
		public String getColumnName() {
			return "Kind";
		}

		@Override
		public Kind getValue(GolangDatatypeRecord rowObject, Settings settings,
				Program program, ServiceProvider services) throws IllegalArgumentException {

			return rowObject.get_kind();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 40;
		}
	}
}
