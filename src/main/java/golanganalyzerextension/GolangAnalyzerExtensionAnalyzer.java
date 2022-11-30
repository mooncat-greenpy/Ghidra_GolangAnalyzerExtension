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
	private static final String RENAME_FUNC="Rename functions";
	private static final String MODIFY_ARG="Modify arguments";
	private static final String ADD_COMMENT="Add comments";
	private static final String DISASM_FUNC="Disassemble functions";
	private static final String ADD_DATATYPE="Add datatypes";
	private static final String EXTENDED_ANALYSIS="Extended analysis";
	private static final String DEBUG_MODE="Debug mode";

	private boolean rename_option;
	private boolean param_option;
	private boolean comment_option;
	private boolean disasm_option;
	private boolean datatype_option;
	private boolean extended_option;
	private boolean debugmode_option;

	public GolangAnalyzerExtensionAnalyzer() {

		super("Golang Analyzer", "Assist in analyzing Golang binaries", AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setSupportsOneTimeAnalysis(true);

		rename_option=true;
		param_option=true;
		comment_option=true;
		disasm_option=false;
		datatype_option=true;
		extended_option=true;
		debugmode_option=false;
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

		options.registerOption(RENAME_FUNC, rename_option, null, "Rename functions");
		options.registerOption(MODIFY_ARG, param_option, null, "Modify function arguments");
		options.registerOption(ADD_COMMENT, comment_option, null, "Add source file and line information to comments");
		options.registerOption(DISASM_FUNC, disasm_option, null, "Disassemble function");
		options.registerOption(ADD_DATATYPE, datatype_option, null, "Add data type");
		options.registerOption(EXTENDED_ANALYSIS, extended_option, null, "Analyze functions in detail");
		options.registerOption(DEBUG_MODE, debugmode_option, null, "Debug mode");
	}

	@Override
	public void optionsChanged(Options options, Program program) {

		rename_option=options.getBoolean(RENAME_FUNC, rename_option);
		param_option=options.getBoolean(MODIFY_ARG, param_option);
		comment_option=options.getBoolean(ADD_COMMENT, comment_option);
		disasm_option=options.getBoolean(DISASM_FUNC, disasm_option);
		datatype_option=options.getBoolean(ADD_DATATYPE, datatype_option);
		extended_option=options.getBoolean(EXTENDED_ANALYSIS, extended_option);
		debugmode_option=options.getBoolean(DEBUG_MODE, debugmode_option);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Logger.set_logger(log, debugmode_option);
		try {
			GolangBinary go_bin=new GolangBinary(program, monitor);
			if(!go_bin.is_ok()) {
				Logger.append_message(String.format("Failed to init GolangBinary"));
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
				Logger.append_message(String.format("Failed to get service"));
				service=new GolangAnalyzerExtensionDummyService();
			}

			FunctionModifier func_modifier=new FunctionModifier(go_bin, service, rename_option, param_option, comment_option, disasm_option, extended_option);
			func_modifier.modify();

			StructureManager struct_manager=new StructureManager(go_bin, program, service, datatype_option);
			struct_manager.modify();

			StringExtractor str_extractor=new StringExtractor(go_bin, service);
			str_extractor.modify();

			service.store_binary(go_bin);
		}catch(Exception e) {
			Logger.append_message(String.format("Error: %s", e.getMessage()));
			return false;
		}

		return true;
	}
}
