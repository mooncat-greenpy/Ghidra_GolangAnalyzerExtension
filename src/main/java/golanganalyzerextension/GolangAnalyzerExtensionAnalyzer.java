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
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.log.Logger;
import golanganalyzerextension.service.GolangAnalyzerExtensionDummyService;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;
import golanganalyzerextension.string.StringExtractor;


public class GolangAnalyzerExtensionAnalyzer extends AbstractAnalyzer {

	public static final String VERSION="1.2.4";
	AnalyzerOption analyzer_option;

	public GolangAnalyzerExtensionAnalyzer() {

		super("Golang Analyzer", String.format("Assists in analyzing Golang binaries (version: %s)", VERSION), AnalyzerType.BYTE_ANALYZER);
		setPriority(AnalysisPriority.LOW_PRIORITY);
		setSupportsOneTimeAnalysis(true);

		analyzer_option=new AnalyzerOption();
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

		analyzer_option.register(options);
	}

	@Override
	public void optionsChanged(Options options, Program program) {

		analyzer_option.change(options);
	}

	@Override
	public boolean added(Program program, AddressSetView set, TaskMonitor monitor, MessageLog log)
			throws CancelledException {
		Logger.set_logger(log, analyzer_option.get_debugmode());
		try {
			GolangBinary go_bin=new GolangBinary(program, analyzer_option.get_go_version(), monitor);

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
			service.store_binary(go_bin);

			StructureManager struct_manager=new StructureManager(go_bin, program, service, analyzer_option.get_datatype());
			struct_manager.modify();

			FunctionModifier func_modifier=new FunctionModifier(go_bin, service, analyzer_option.get_rename(), analyzer_option.get_param(), analyzer_option.get_comment(), analyzer_option.get_disasm());
			func_modifier.modify();

			if(analyzer_option.get_string()) {
				StringExtractor str_extractor=new StringExtractor(go_bin, service);
				str_extractor.modify();
			}
		} catch(InvalidBinaryStructureException e) {
			Logger.append_message(e.getMessage());
		} catch(Exception e) {
			Logger.append_message(String.format("Error: %s", e.getMessage()));
			return false;
		}

		return true;
	}
}
