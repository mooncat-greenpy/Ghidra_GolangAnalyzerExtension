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
	public GolangAnalyzerExtensionAnalyzer() {

		super("Golang Analyzer", "Assist in analyzing Golang binaries", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.HIGHEST_PRIORITY);
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

		// TODO: If this analyzer has custom options, register them here

		options.registerOption("Option name goes here", false, null,
			"Option description goes here");
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {

		FunctionModifier func_modifier=new FunctionModifier(program, monitor, log);
		func_modifier.modify();

		return false;
	}
}
