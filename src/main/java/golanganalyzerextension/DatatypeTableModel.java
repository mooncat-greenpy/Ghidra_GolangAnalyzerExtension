package golanganalyzerextension;

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

public class DatatypeTableModel extends AddressBasedTableModel<GolangDatatype> {
	PluginTool plugin_tool;

	DatatypeTableModel(PluginTool tool, Program program, TaskMonitor monitor) {
		super("Datatypes Table", tool, program, monitor, true);

		plugin_tool=tool;
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {
		AddressSet address_set = new AddressSet();
		for (int row : rows) {
			GolangDatatype go_datatype = getRowObject(row);
			Address addr = go_datatype.addr;
			if (addr != null) {
				address_set.addRange(addr, addr);
			}
		}
		return new ProgramSelection(address_set);
	}

	@Override
	public Address getAddress(int row) {
		GolangDatatype go_datatype = getRowObject(row);
		return go_datatype.addr;
	}

	public void update_table(Program new_program) {
		setProgram(new_program);
		reload();
	}

	@Override
	protected void doLoad(Accumulator<GolangDatatype> accumulator, TaskMonitor monitor)
			throws CancelledException {
		Map<Long, GolangDatatype> datatype_map=null;
		GolangAnalyzerExtensionService service=plugin_tool.getService(GolangAnalyzerExtensionService.class);
		datatype_map=service.get_datatype_map();
		if(datatype_map==null) {
			return;
		}
		for(Map.Entry<Long, GolangDatatype> entry : datatype_map.entrySet()) {
			accumulator.add(entry.getValue());
		}
	}

	@Override
	protected TableColumnDescriptor<GolangDatatype> createTableColumnDescriptor() {
		TableColumnDescriptor<GolangDatatype> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new DatatypeNameTableColumn());
		descriptor.addVisibleColumn(new DatatypeSizeTableColumn());
		descriptor.addVisibleColumn(new DatatypeKindTableColumn());

		return descriptor;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================


	static class DatatypeNameTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangDatatype, String> {
		@Override
		public String getColumnName() {
			return "Struct Name";
		}

		@Override
		public String getValue(GolangDatatype rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.get_name();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	static class DatatypeSizeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangDatatype, Integer> {
		@Override
		public String getColumnName() {
			return "Size";
		}

		@Override
		public Integer getValue(GolangDatatype rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {

			return (int)rowObject.size;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	static class DatatypeKindTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangDatatype, Kind> {
		@Override
		public String getColumnName() {
			return "Kind";
		}

		@Override
		public Kind getValue(GolangDatatype rowObject, Settings settings,
				Program program, ServiceProvider services) throws IllegalArgumentException {

			return rowObject.get_kind();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 40;
		}
	}
}
