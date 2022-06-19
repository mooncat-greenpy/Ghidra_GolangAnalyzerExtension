package golanganalyzerextension;

import java.util.List;

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

public class FilenameTableModel extends AddressBasedTableModel<String> {
	PluginTool plugin_tool;

	FilenameTableModel(PluginTool tool, Program program, TaskMonitor monitor) {
		super("Functions Table", tool, program, monitor, true);

		plugin_tool=tool;
	}

	/*@Override
	public ProgramSelection getProgramSelection(int[] rows) {

		AddressSet address_set = new AddressSet();
		for (int row : rows) {
			String gofunc = getRowObject(row);
			Address addr = gofunc.get_func_addr();
			if (addr != null) {
				address_set.addRange(addr, addr.add(gofunc.func_size));
			}
		}
		return new ProgramSelection(address_set);
	}

	*/@Override
	public Address getAddress(int row) {
		return null;
	}

	public void update_table(Program new_program) {
		setProgram(new_program);
		reload();
	}

	@Override
	protected void doLoad(Accumulator<String> accumulator, TaskMonitor monitor)
			throws CancelledException {
		List<String> filename_list=null;
		GolangAnalyzerExtensionService service=plugin_tool.getService(GolangAnalyzerExtensionService.class);
		filename_list=service.get_filename_list();
		if(filename_list==null) {
			return;
		}
		for(String filename : filename_list) {
			accumulator.add(filename);
		}
	}

	@Override
	protected TableColumnDescriptor<String> createTableColumnDescriptor() {
		TableColumnDescriptor<String> descriptor = new TableColumnDescriptor<>();
		descriptor.addVisibleColumn(new FilenameTableColumn());

		return descriptor;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	static class FilenameTableColumn
			extends AbstractProgramBasedDynamicTableColumn<String, String> {
		@Override
		public String getColumnName() {
			return "Filename";
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
