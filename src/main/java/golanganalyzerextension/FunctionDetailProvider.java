package golanganalyzerextension;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.listing.Parameter;
import ghidra.util.layout.VerticalLayout;

public class FunctionDetailProvider extends ComponentProviderAdapter {

	JPanel main_panel;

	public FunctionDetailProvider(GolangAnalyzerExtensionPlugin tool, GolangFunction gofunc) {
		super(tool.getTool(), "GolangFunctionDetail", tool.getName());

		main_panel=create_main_panel(gofunc);

		setTitle(gofunc.get_func_name());
		addToTool();
	}

	JPanel create_main_panel(GolangFunction gofunc) {
		JPanel panel=new JPanel(new BorderLayout());
		panel.add(create_info_panel(gofunc), BorderLayout.WEST);

		JPanel table_panel=new JPanel(new GridLayout(2, 1));
		table_panel.add(create_params_table(gofunc), BorderLayout.NORTH);
		table_panel.add(create_file_line_table(gofunc), BorderLayout.CENTER);
		panel.add(table_panel, BorderLayout.CENTER);

		panel.setPreferredSize(new Dimension(900, 600));
		return panel;
	}

	private JPanel create_info_panel(GolangFunction gofunc) {
		JPanel panel = new JPanel(new VerticalLayout(0));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JLabel name_panel=new JLabel(String.format("Name: %s", gofunc.get_func_name()));
		name_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
		panel.add(name_panel);
		JLabel start_address_panel=new JLabel(String.format("Start address: %d", gofunc.get_func_addr().getOffset()));
		start_address_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
		panel.add(start_address_panel);
		JLabel end_address_panel=new JLabel(String.format("End address: %d", gofunc.get_func_addr().add(gofunc.func_size).getOffset()));
		end_address_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
		panel.add(end_address_panel);
		JLabel args_length_panel=new JLabel(String.format("Args Num: %d", gofunc.get_params().size()));
		args_length_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
		panel.add(args_length_panel);

		return panel;
	}

	private JScrollPane create_params_table(GolangFunction gofunc) {
		List<Parameter> params=gofunc.get_params();
		String[] columns={"Name", "Datatype", "Length"};
		Object[][] data=new Object[params.size()][3];
		for(int i=0; i<params.size(); i++) {
			Parameter p=params.get(i);
			Object[] row={p.getName(), p.getDataType().getName(), p.getLength()};
			data[i]=row;
		}
		JTable table=new JTable(data, columns);
		table.setEnabled(false);
		return new JScrollPane(table);
	}

	private JScrollPane create_file_line_table(GolangFunction gofunc) {
		Map<Integer, String> file_line_map=gofunc.get_file_line_comment_map();
		List<Integer> key_list=new ArrayList<Integer>(file_line_map.keySet());
		key_list.sort(null);
		String[] columns={"Offset", "File name"};
		Object[][] data=new Object[file_line_map.size()][2];
		for(int i=0; i<key_list.size(); i++) {
			Object[] row={key_list.get(i), file_line_map.get(key_list.get(i))};
			data[i]=row;
		}
		JTable table=new JTable(data, columns);
		table.setEnabled(false);
		return new JScrollPane(table);
	}

	@Override
	public JComponent getComponent() {
		return main_panel;
	}
}