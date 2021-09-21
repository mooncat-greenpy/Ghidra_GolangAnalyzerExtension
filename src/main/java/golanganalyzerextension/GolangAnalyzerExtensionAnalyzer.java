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
	boolean datatype_option=true;
	boolean debugmode_option=false;

	public GolangAnalyzerExtensionAnalyzer() {

		super("Golang Analyzer", "Assist in analyzing Golang binaries", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY);
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
		options.registerOption("Add data type", datatype_option, null, "Add data type");
		options.registerOption("Debug mode", debugmode_option, null, "Debug mode");
	}

	@Override
	public void optionsChanged(Options options, Program program) {

		rename_option=options.getBoolean("Rename functions", rename_option);
		param_option=options.getBoolean("Modify arguments", param_option);
		comment_option=options.getBoolean("Add comment", comment_option);
		datatype_option=options.getBoolean("Add data type", datatype_option);
		debugmode_option=options.getBoolean("Debug mode", debugmode_option);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		try {
			FunctionModifier func_modifier=new FunctionModifier(program, monitor, log, rename_option, param_option, comment_option, debugmode_option);
			func_modifier.modify();

			StructureManager struct_manager=new StructureManager(program, monitor, log, datatype_option, debugmode_option);
			struct_manager.modify();
		}catch(Exception e) {
			log.appendMsg(String.format("Error: %s", e.getMessage()));
		}

		return false;
	}
}
