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

	GolangAnalyzerExtensionPlugin gae_plugin;

	private JPanel main_panel;
	private Program current_program;
	private boolean is_info_panel_showing = true;

	private GhidraTable function_table;
	private FunctionTableModel function_model;
	private GhidraThreadedTablePanel<GolangFunction> function_threaded_table_panel;
	private GhidraTableFilterPanel<GolangFunction> function_filter_panel;

	private GhidraTable filename_table;
	private FilenameTableModel filename_model;
	private GhidraThreadedTablePanel<String> filename_threaded_table_panel;
	private GhidraTableFilterPanel<String> filename_filter_panel;

	private GhidraTable datatype_table;
	private DatatypeTableModel datatype_model;
	private GhidraThreadedTablePanel<GolangDatatype> datatype_threaded_table_panel;
	private GhidraTableFilterPanel<GolangDatatype> datatype_filter_panel;

	private JPanel info_panel;
	private JButton function_toggle_show_info_panel_button;
	private JButton filename_toggle_show_info_panel_button;
	private JButton datatype_toggle_show_info_panel_button;
	private JButton refresh_button;

	public GolangAnalyzerExtensionProvider(GolangAnalyzerExtensionPlugin plugin) {
		super(plugin.getTool(), "GolangAnalyzerExtension", plugin.getName());

		gae_plugin=plugin;
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

		datatype_threaded_table_panel.dispose();
		datatype_filter_panel.dispose();
		datatype_table.dispose();
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

		GolangBinary go_bin=gae_plugin.get_binary();
		int func_list_size=gae_plugin.get_function_list().size();
		int filename_list_size=gae_plugin.get_filename_list().size();
		int datatype_map_size=gae_plugin.get_datatype_map().size();
		if(go_bin!=null) {
			JLabel name_panel=new JLabel(String.format("Name: %s", go_bin.get_name()));
			name_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
			panel.add(name_panel);
			JLabel go_version_panel=new JLabel(String.format("Go version: %s", go_bin.get_go_version()));
			go_version_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
			panel.add(go_version_panel);
			JLabel pointer_size_panel=new JLabel(String.format("Pointer size: %d", go_bin.get_pointer_size()));
			pointer_size_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
			panel.add(pointer_size_panel);
			JLabel func_num_panel=new JLabel(String.format("Number of functions: %d", func_list_size));
			func_num_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
			panel.add(func_num_panel);
			JLabel filename_num_panel=new JLabel(String.format("Number of filenames: %d", filename_list_size));
			filename_num_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
			panel.add(filename_num_panel);
			JLabel datatype_num_panel=new JLabel(String.format("Number of datatyeps: %d", datatype_map_size));
			datatype_num_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
			panel.add(datatype_num_panel);
		}

		refresh_button = new JButton(Icons.REFRESH_ICON);
		refresh_button.setText("Refresh");
		refresh_button.addActionListener(e -> {
			function_model.update_table(current_program);
			filename_model.update_table(current_program);
			datatype_model.update_table(current_program);
			toggle_show_info_panel();
			toggle_show_info_panel();
		});
		panel.add(refresh_button);

		return panel;
	}

	private class FunctionTable extends GhidraTable {
		public FunctionTable(ThreadedTableModel<GolangFunction, ?> model) {
			super(model);
		}
	}

	private class FilenameTable extends GhidraTable {
		public FilenameTable(ThreadedTableModel<String, ?> model) {
			super(model);
		}
	}

	private class DatatypeTable extends GhidraTable {
		public DatatypeTable(ThreadedTableModel<GolangDatatype, ?> model) {
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

		filename_model = new FilenameTableModel(tool, current_program, null);
		filename_threaded_table_panel = new GhidraThreadedTablePanel<>(filename_model, 1000) {
			@Override
			protected GTable createTable(ThreadedTableModel<String, ?> model) {
				return new FilenameTable(model);
			}
		};
		filename_table = filename_threaded_table_panel.getTable();
		filename_table.setActionsEnabled(true);
		filename_table.setName("Filename");
		filename_table.setPreferredScrollableViewportSize(new Dimension(350, 150));
		filename_table.installNavigation(go_to_service, go_to_service.getDefaultNavigatable());
		filename_filter_panel = new GhidraTableFilterPanel<>(filename_table, filename_model);

		datatype_model = new DatatypeTableModel(tool, current_program, null);
		datatype_threaded_table_panel = new GhidraThreadedTablePanel<>(datatype_model, 1000) {
			@Override
			protected GTable createTable(ThreadedTableModel<GolangDatatype, ?> model) {
				return new DatatypeTable(model);
			}
		};
		datatype_table = datatype_threaded_table_panel.getTable();
		datatype_table.setActionsEnabled(true);
		datatype_table.setName("DataTable");
		datatype_table.setPreferredScrollableViewportSize(new Dimension(350, 150));
		datatype_table.installNavigation(go_to_service, go_to_service.getDefaultNavigatable());
		datatype_filter_panel = new GhidraTableFilterPanel<>(datatype_table, datatype_model);

		function_toggle_show_info_panel_button = new JButton(COLLAPSE_ICON);
		function_toggle_show_info_panel_button.setToolTipText("Toggle Info Panel On/Off");
		function_toggle_show_info_panel_button.addActionListener(e -> toggle_show_info_panel());

		filename_toggle_show_info_panel_button = new JButton(COLLAPSE_ICON);
		filename_toggle_show_info_panel_button.setToolTipText("Toggle Info Panel On/Off");
		filename_toggle_show_info_panel_button.addActionListener(e -> toggle_show_info_panel());

		datatype_toggle_show_info_panel_button = new JButton(COLLAPSE_ICON);
		datatype_toggle_show_info_panel_button.setToolTipText("Toggle Info Panel On/Off");
		datatype_toggle_show_info_panel_button.addActionListener(e -> toggle_show_info_panel());

		JPanel function_panel = new JPanel(new BorderLayout());
		function_panel.add(function_threaded_table_panel, BorderLayout.CENTER);
		JPanel function_bottom_panel = new JPanel(new BorderLayout());
		function_bottom_panel.add(function_filter_panel, BorderLayout.CENTER);
		function_bottom_panel.add(function_toggle_show_info_panel_button, BorderLayout.EAST);
		function_panel.add(function_bottom_panel, BorderLayout.SOUTH);

		JPanel filename_panel = new JPanel(new BorderLayout());
		filename_panel.add(filename_threaded_table_panel, BorderLayout.CENTER);
		JPanel filename_bottom_panel = new JPanel(new BorderLayout());
		filename_bottom_panel.add(filename_filter_panel, BorderLayout.CENTER);
		filename_bottom_panel.add(filename_toggle_show_info_panel_button, BorderLayout.EAST);
		filename_panel.add(filename_bottom_panel, BorderLayout.SOUTH);

		JPanel datatype_panel = new JPanel(new BorderLayout());
		datatype_panel.add(datatype_threaded_table_panel, BorderLayout.CENTER);
		JPanel datatype_bottom_panel = new JPanel(new BorderLayout());
		datatype_bottom_panel.add(datatype_filter_panel, BorderLayout.CENTER);
		datatype_bottom_panel.add(datatype_toggle_show_info_panel_button, BorderLayout.EAST);
		datatype_panel.add(datatype_bottom_panel, BorderLayout.SOUTH);

		JTabbedPane tabbed_pane=new JTabbedPane();
		tabbed_pane.add("functions", function_panel);
		tabbed_pane.add("filenames", filename_panel);
		tabbed_pane.add("datatypes", datatype_panel);
		return tabbed_pane;
	}

	protected void toggle_show_info_panel() {
		is_info_panel_showing = !is_info_panel_showing;

		if (is_info_panel_showing) {
			function_toggle_show_info_panel_button.setIcon(COLLAPSE_ICON);
			filename_toggle_show_info_panel_button.setIcon(COLLAPSE_ICON);
			datatype_toggle_show_info_panel_button.setIcon(COLLAPSE_ICON);
			info_panel=create_info_panel();
			main_panel.add(info_panel, BorderLayout.WEST);
		}
		else {
			function_toggle_show_info_panel_button.setIcon(EXPAND_ICON);
			filename_toggle_show_info_panel_button.setIcon(EXPAND_ICON);
			datatype_toggle_show_info_panel_button.setIcon(EXPAND_ICON);
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
			filename_model.setProgram(program);
			filename_model.reload();
			datatype_model.setProgram(program);
			datatype_model.reload();
		}
	}

	@Override
	public JComponent getComponent() {
		return main_panel;
	}

	@Override
	public void domainObjectChanged(DomainObjectChangedEvent ev) {
		function_table.repaint();
		filename_table.repaint();
		datatype_table.repaint();
	}
}