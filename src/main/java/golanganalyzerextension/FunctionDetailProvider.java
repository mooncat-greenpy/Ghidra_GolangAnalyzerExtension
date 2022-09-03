package golanganalyzerextension;

import javax.swing.JComponent;
import javax.swing.JPanel;

import ghidra.framework.plugintool.ComponentProviderAdapter;

public class FunctionDetailProvider extends ComponentProviderAdapter {

	JPanel main_panel;

	public FunctionDetailProvider(GolangAnalyzerExtensionPlugin tool, GolangFunction gofunc) {
		super(tool.getTool(), "GolangFunctionDetail", tool.getName());

		main_panel=create_main_panel(gofunc);

		setTitle(gofunc.func_name);
		addToTool();
	}

	JPanel create_main_panel(GolangFunction gofunc) {
		JPanel panel = new JPanel();
		return panel;
	}

	@Override
	public JComponent getComponent() {
		return main_panel;
	}
}