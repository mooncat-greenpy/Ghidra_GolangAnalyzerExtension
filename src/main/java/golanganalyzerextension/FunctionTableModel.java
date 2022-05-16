package golanganalyzerextension;

import java.util.List;

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

public class FunctionTableModel extends AddressBasedTableModel<GolangFunction> {
	PluginTool plugin_tool;

	FunctionTableModel(PluginTool tool, Program program, TaskMonitor monitor) {
		super("Functions Table", tool, program, monitor, true);

		plugin_tool=tool;
	}

	@Override
	public ProgramSelection getProgramSelection(int[] rows) {

		AddressSet address_set = new AddressSet();
		for (int row : rows) {
			GolangFunction gofunc = getRowObject(row);
			Address addr = gofunc.get_func_addr();
			if (addr != null) {
				address_set.addRange(addr, addr.add(gofunc.func_size));
			}
		}
		return new ProgramSelection(address_set);
	}

	@Override
	public Address getAddress(int row) {
		GolangFunction gofunc = getRowObject(row);
		return gofunc.get_func_addr();
	}

	public void update_table(Program new_program) {
		setProgram(new_program);
		reload();
	}

	@Override
	protected void doLoad(Accumulator<GolangFunction> accumulator, TaskMonitor monitor)
			throws CancelledException {
		List<GolangFunction> func_list=null;
		GolangAnalyzerExtensionService service=plugin_tool.getService(GolangAnalyzerExtensionService.class);
		func_list=service.get_function_list();
		if(func_list==null) {
			return;
		}
		for(GolangFunction gofunc : func_list) {
			accumulator.add(gofunc);
		}
	}

	@Override
	protected TableColumnDescriptor<GolangFunction> createTableColumnDescriptor() {
		TableColumnDescriptor<GolangFunction> descriptor = new TableColumnDescriptor<>();
		// Error: empty
		// descriptor.addVisibleColumn(DiscoverableTableUtils.adaptColumForModel(this, new AddressTableColumn()), 0, true);
		descriptor.addVisibleColumn(new FunctionAddressTableColumn());
		descriptor.addVisibleColumn(new FunctionNameTableColumn());
		descriptor.addVisibleColumn(new FunctionArgsSizeTableColumn());
		descriptor.addVisibleColumn(new FunctionSizeTableColumn());

		return descriptor;
	}

//==================================================================================================
// Inner Classes
//==================================================================================================

	static class FunctionAddressTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangFunction, AddressBasedLocation> {
		@Override
		public String getColumnName() {
			return "Location";
		}

		@Override
		public AddressBasedLocation getValue(GolangFunction rowObject, Settings settings, Program pgm,
				ServiceProvider serviceProvider) throws IllegalArgumentException {
			return new AddressBasedLocation(pgm, rowObject.get_func_addr());
		}

		@Override
		public int getColumnPreferredWidth() {
			return 200;
		}
	}

	static class FunctionNameTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangFunction, String> {
		@Override
		public String getColumnName() {
			return "Function Name";
		}

		@Override
		public String getValue(GolangFunction rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {
			return rowObject.get_func_name();
		}

		@Override
		public int getColumnPreferredWidth() {
			return 100;
		}
	}

	static class FunctionArgsSizeTableColumn
	extends AbstractProgramBasedDynamicTableColumn<GolangFunction, Integer> {
		@Override
		public String getColumnName() {
			return "Args Size";
		}

		@Override
		public Integer getValue(GolangFunction rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {
			return (int)rowObject.arg_size;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}

	static class FunctionSizeTableColumn
			extends AbstractProgramBasedDynamicTableColumn<GolangFunction, Integer> {
		@Override
		public String getColumnName() {
			return "Size";
		}

		@Override
		public Integer getValue(GolangFunction rowObject, Settings settings, Program program,
				ServiceProvider services) throws IllegalArgumentException {
			return (int)rowObject.func_size;
		}

		@Override
		public int getColumnPreferredWidth() {
			return 80;
		}
	}
}
