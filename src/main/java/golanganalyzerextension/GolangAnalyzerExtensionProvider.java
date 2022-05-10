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
import resources.ResourceManager;

public class GolangAnalyzerExtensionProvider extends ComponentProviderAdapter implements DomainObjectListener {
	private static final Icon REFRESH_ICON = ResourceManager.loadImage("images/reload.png");
	private static final Icon EXPAND_ICON = ResourceManager.loadImage("images/expand.gif");
	private static final Icon COLLAPSE_ICON = ResourceManager.loadImage("images/collapse.gif");

	private JPanel main_panel;
	private Program current_program;
	private boolean is_info_panel_showing = true;

	private GhidraTable table;
	private FunctionTableModel function_model;
	private GhidraThreadedTablePanel<GolangFunction> threaded_table_panel;
	private GhidraTableFilterPanel<GolangFunction> filter_panel;

	private JPanel make_info_panel;
	private JButton toggle_show_make_info_panel_button;
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
		threaded_table_panel.dispose();
		filter_panel.dispose();
		table.dispose();
	}

	private JPanel create_main_panel() {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(create_tab_panel(), BorderLayout.CENTER);
		make_info_panel = create_make_info_panel();
		panel.add(make_info_panel, BorderLayout.WEST);
		panel.setPreferredSize(new Dimension(900, 600));
		return panel;

	}

	private JPanel create_make_info_panel() {
		JPanel panel = new JPanel(new VerticalLayout(0));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		panel.add(new JLabel("Refresh"));
		refresh_button = new JButton(REFRESH_ICON);
		refresh_button.addActionListener(e -> function_model.update_table(current_program));
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

		threaded_table_panel = new GhidraThreadedTablePanel<>(function_model, 1000) {
			@Override
			protected GTable createTable(ThreadedTableModel<GolangFunction, ?> model) {
				return new FunctionTable(model);
			}
		};
		table = threaded_table_panel.getTable();
		table.setActionsEnabled(true);
		table.setName("DataTable");
		table.setPreferredScrollableViewportSize(new Dimension(350, 150));

		GoToService go_to_service = tool.getService(GoToService.class);
		table.installNavigation(go_to_service, go_to_service.getDefaultNavigatable());

		filter_panel = new GhidraTableFilterPanel<>(table, function_model);

		toggle_show_make_info_panel_button = new JButton(COLLAPSE_ICON);
		toggle_show_make_info_panel_button.setToolTipText("Toggle Make Strings Panel On/Off");
		toggle_show_make_info_panel_button.addActionListener(e -> toggle_show_make_info_panel());

		JPanel panel = new JPanel(new BorderLayout());
		panel.add(threaded_table_panel, BorderLayout.CENTER);
		JPanel bottom_panel = new JPanel(new BorderLayout());
		bottom_panel.add(filter_panel, BorderLayout.CENTER);
		bottom_panel.add(toggle_show_make_info_panel_button, BorderLayout.EAST);
		panel.add(bottom_panel, BorderLayout.SOUTH);

		JTabbedPane tabbed_pane=new JTabbedPane();
		tabbed_pane.add("functions", panel);
		return tabbed_pane;
	}

	protected void toggle_show_make_info_panel() {
		is_info_panel_showing = !is_info_panel_showing;

		if (is_info_panel_showing) {
			toggle_show_make_info_panel_button.setIcon(COLLAPSE_ICON);
			main_panel.add(make_info_panel, BorderLayout.WEST);
		}
		else {
			toggle_show_make_info_panel_button.setIcon(EXPAND_ICON);
			main_panel.remove(make_info_panel);
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
		table.repaint();
	}
}
