package golanganalyzerextension;

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.services.GoToService;
import ghidra.framework.plugintool.PluginInfo;
import ghidra.framework.plugintool.PluginTool;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;
import ghidra.program.util.ProgramSelection;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = CorePluginPackage.NAME,
	category = PluginCategoryNames.COMMON,
	shortDescription = "GolangAnalyzerExtension",
	description = "Displays GolangAnalyzerExtension analysis results",
	servicesRequired = { GoToService.class }
)
//@formatter:on
public class GolangAnalyzerExtensionPlugin extends ProgramPlugin {
	private GolangAnalyzerExtensionProvider gae_provider;

	public GolangAnalyzerExtensionPlugin(PluginTool tool) {
		super(tool, false, true);
	}

	/**
	 * @see ghidra.framework.plugintool.Plugin#init()
	 */
	@Override
	protected void init() {
		super.init();
		create_GolangAnalyzerExtension_provider();
	}

	public void setSelection(ProgramSelection selection) {
		currentSelection = selection;
	}

	/**
	 * @see ghidra.framework.plugintool.Plugin#dispose()
	 */
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
}
