package golanganalyzerextension;

import java.awt.*;

import javax.swing.*;

import docking.widgets.table.*;
import docking.widgets.table.threaded.ThreadedTableModel;
import ghidra.app.services.GoToService;
import ghidra.framework.model.DomainObjectChangedEvent;
import ghidra.framework.model.DomainObjectListener;
import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Program;
import ghidra.util.layout.VerticalLayout;
import ghidra.util.table.*;
import resources.Icons;
import resources.ResourceManager;

public class GolangAnalyzerExtensionProvider extends ComponentProviderAdapter implements DomainObjectListener {
	private static final Icon EXPAND_ICON = ResourceManager.loadImage("images/expand.gif");
	private static final Icon COLLAPSE_ICON = ResourceManager.loadImage("images/collapse.gif");

	private JPanel main_panel;
	private Program current_program;
	private boolean is_info_panel_showing = true;

	private GhidraTable function_table;
	private FunctionTableModel function_model;
	private GhidraThreadedTablePanel<GolangFunction> function_threaded_table_panel;
	private GhidraTableFilterPanel<GolangFunction> function_filter_panel;

	private JPanel info_panel;
	private JButton function_toggle_show_info_panel_button;
	private JButton refresh_button;

	public GolangAnalyzerExtensionProvider(GolangAnalyzerExtensionPlugin plugin) {
		super(plugin.getTool(), "GolangAnalyzerExtension", plugin.getName());

		main_panel = create_main_panel();
		setTitle("GolangAnalyzerExtension");
		setWindowMenuGroup("GolangAnalyzerExtension");
		setWindowGroup("GolangAnalyzerExtension");

		addToTool();
	}

	void dispose() {
		function_threaded_table_panel.dispose();
		function_filter_panel.dispose();
		function_table.dispose();
	}

	private JPanel create_main_panel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(create_tab_panel(), BorderLayout.CENTER);
		info_panel = create_info_panel();
		panel.add(info_panel, BorderLayout.WEST);
		panel.setPreferredSize(new Dimension(900, 600));
		return panel;

	}

	private JPanel create_info_panel() {
		JPanel panel = new JPanel(new VerticalLayout(0));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		panel.add(new JLabel("Refresh"));
		refresh_button = new JButton(Icons.REFRESH_ICON);
		refresh_button.addActionListener(e -> {
			function_model.update_table(current_program);
		});
		panel.add(refresh_button);

		return panel;
	}

	private class FunctionTable extends GhidraTable {
		public FunctionTable(ThreadedTableModel<GolangFunction, ?> model) {
			super(model);
		}
	}

	private JComponent create_tab_panel() {
		function_model = new FunctionTableModel(tool, current_program, null);
		function_threaded_table_panel = new GhidraThreadedTablePanel<>(function_model, 1000) {
			@Override
			protected GTable createTable(ThreadedTableModel<GolangFunction, ?> model) {
				return new FunctionTable(model);
			}
		};
		function_table = function_threaded_table_panel.getTable();
		function_table.setActionsEnabled(true);
		function_table.setName("DataTable");
		function_table.setPreferredScrollableViewportSize(new Dimension(350, 150));
		GoToService go_to_service = tool.getService(GoToService.class);
		function_table.installNavigation(go_to_service, go_to_service.getDefaultNavigatable());
		function_filter_panel = new GhidraTableFilterPanel<>(function_table, function_model);

		function_toggle_show_info_panel_button = new JButton(COLLAPSE_ICON);
		function_toggle_show_info_panel_button.setToolTipText("Toggle Info Panel On/Off");
		function_toggle_show_info_panel_button.addActionListener(e -> toggle_show_info_panel());

		JPanel function_panel = new JPanel(new BorderLayout());
		function_panel.add(function_threaded_table_panel, BorderLayout.CENTER);
		JPanel function_bottom_panel = new JPanel(new BorderLayout());
		function_bottom_panel.add(function_filter_panel, BorderLayout.CENTER);
		function_bottom_panel.add(function_toggle_show_info_panel_button, BorderLayout.EAST);
		function_panel.add(function_bottom_panel, BorderLayout.SOUTH);

		JTabbedPane tabbed_pane=new JTabbedPane();
		tabbed_pane.add("functions", function_panel);
		return tabbed_pane;
	}

	protected void toggle_show_info_panel() {
		is_info_panel_showing = !is_info_panel_showing;

		if (is_info_panel_showing) {
			function_toggle_show_info_panel_button.setIcon(COLLAPSE_ICON);
			main_panel.add(info_panel, BorderLayout.WEST);
		}
		else {
			function_toggle_show_info_panel_button.setIcon(EXPAND_ICON);
			main_panel.remove(info_panel);
		}
		main_panel.validate();
	}

	public void setProgram(Program program) {
		if (program == current_program) {
			return;
		}
		if (current_program != null) {
			current_program.removeListener(this);
		}

		current_program = program;

		if (current_program != null) {
			current_program.addListener(this);
		}

		if (isVisible()) {
			function_model.setProgram(program);
			function_model.reload();
		}
	}

	@Override
	public JComponent getComponent() {
		return main_panel;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		function_table.repaint();
	}
}
