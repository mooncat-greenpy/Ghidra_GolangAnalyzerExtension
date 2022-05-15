package golanganalyzerextension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "GolangAnalyzerExtension",
	description = "Displays GolangAnalyzerExtension analysis results",
	servicesProvided = { GolangAnalyzerExtensionService.class },
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class GolangAnalyzerExtensionPlugin extends ProgramPlugin implements GolangAnalyzerExtensionService {
	private GolangAnalyzerExtensionProvider gae_provider;

	public GolangAnalyzerExtensionPlugin(PluginTool tool) {
		super(tool, false, true);
	}

	@Override
	protected void init() {
		super.init();
		create_GolangAnalyzerExtension_provider();
	}

	@Override
	public void dispose() {
		gae_provider.closeComponent();
		gae_provider.dispose();

		super.dispose();
	}

	@Override
	protected void programActivated(Program program) {
		gae_provider.setProgram(program);
	}

	public void create_GolangAnalyzerExtension_provider() {
		gae_provider = new GolangAnalyzerExtensionProvider(this);
		gae_provider.setProgram(currentProgram);
		gae_provider.setVisible(true);
	}

	GolangBinary go_bin=null;
	List<GolangFunction> func_list=new ArrayList<>();
	Map<Long, GolangDatatype> datatype_map=new HashMap<>();

	@Override
	public GolangBinary get_binary() {
		return go_bin;
	}

	@Override
	public void store_binary(GolangBinary bin) {
		go_bin=bin;
	}

	@Override
	public List<GolangFunction> get_function_list() {
		return func_list;
	}

	@Override
	public void store_function_list(List<GolangFunction> list) {
		func_list=list;
	}

	@Override
	public Map<Long, GolangDatatype> get_datatype_map() {
		return datatype_map;
	}

	@Override
	public void store_datatype_map(Map<Long, GolangDatatype> map) {
		datatype_map=map;
	}
}
