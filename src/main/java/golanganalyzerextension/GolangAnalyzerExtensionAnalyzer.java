package golanganalyzerextension;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;


public class GolangAnalyzerExtensionAnalyzer extends AbstractAnalyzer {
	boolean rename_option=true;
	boolean param_option=true;
	boolean comment_option=true;

	public GolangAnalyzerExtensionAnalyzer() {

		super("Golang Analyzer", "Assist in analyzing Golang binaries", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.HIGHEST_PRIORITY);
		setSupportsOneTimeAnalysis(true);
	}

	@Override
	public boolean getDefaultEnablement(Program program) {

		return true;
	}

	@Override
	public boolean canAnalyze(Program program) {

		return true;
	}

	@Override
	public void registerOptions(Options options, Program program) {

		options.registerOption("Rename functions", rename_option, null, "Rename functions");
		options.registerOption("Modify arguments", param_option, null, "Modify function arguments");
		options.registerOption("Add comment", comment_option, null, "Add source file and line information to comments");
	}

	@Override
	public void optionsChanged(Options options, Program program) {

		rename_option=options.getBoolean("Rename functions", rename_option);
		param_option=options.getBoolean("Modify arguments", param_option);
		comment_option=options.getBoolean("Add comment", comment_option);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		FunctionModifier func_modifier=new FunctionModifier(program, monitor, log);
		func_modifier.modify(rename_option, param_option, comment_option);

		StructureManager struct_manager=new StructureManager(program, monitor, log, func_modifier.base, func_modifier.pointer_size);

		return false;
	}
}
