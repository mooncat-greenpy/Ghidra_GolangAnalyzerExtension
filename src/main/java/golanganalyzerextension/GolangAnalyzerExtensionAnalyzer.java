package golanganalyzerextension;

import ghidra.app.services.AbstractAnalyzer;
import ghidra.app.services.AnalysisPriority;
import ghidra.app.services.AnalyzerType;
import ghidra.app.util.importer.MessageLog;
import ghidra.framework.options.Options;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.AddressSetView;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;


public class GolangAnalyzerExtensionAnalyzer extends AbstractAnalyzer {
	boolean rename_option=true;
	boolean param_option=true;
	boolean comment_option=true;
	boolean disasm_option=true;
	boolean datatype_option=true;
	boolean extended_option=true;
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
		options.registerOption("Disassemble function", disasm_option, null, "Disassemble function");
		options.registerOption("Add data type", datatype_option, null, "Add data type");
		options.registerOption("Extended analysis", extended_option, null, "Analyze functions in detail");
		options.registerOption("Debug mode", debugmode_option, null, "Debug mode");
	}

	@Override
	public void optionsChanged(Options options, Program program) {

		rename_option=options.getBoolean("Rename functions", rename_option);
		param_option=options.getBoolean("Modify arguments", param_option);
		comment_option=options.getBoolean("Add comment", comment_option);
		disasm_option=options.getBoolean("Disassemble function", disasm_option);
		datatype_option=options.getBoolean("Add data type", datatype_option);
		extended_option=options.getBoolean("Extended analysis", extended_option);
		debugmode_option=options.getBoolean("Debug mode", debugmode_option);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		try {
			Logger.set_logger(log, debugmode_option);
			GolangBinary go_bin=new GolangBinary(program, monitor);
			if(!go_bin.is_ok()) {
				log.appendMsg(String.format("Failed to init GolangBinary"));
				return false;
			}

			GolangAnalyzerExtensionService service=null;
			for(Object obj : program.getConsumerList()) {
				if(!(obj instanceof PluginTool)) {
					continue;
				}
				PluginTool plugin_tool=(PluginTool)obj;
				service=plugin_tool.getService(GolangAnalyzerExtensionService.class);
				break;
			}
			if(service==null) {
				log.appendMsg(String.format("Failed to get service"));
				return false;
			}

			FunctionModifier func_modifier=new FunctionModifier(go_bin, service, rename_option, param_option, comment_option, disasm_option, extended_option);
			func_modifier.modify();

			StructureManager struct_manager=new StructureManager(go_bin, program, service, datatype_option);
			struct_manager.modify();

			service.store_binary(go_bin);
		}catch(Exception e) {
			log.appendMsg(String.format("Error: %s", e.getMessage()));
			return false;
		}

		return true;
	}
}
