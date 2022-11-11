package golanganalyzerextension;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;

import ghidra.framework.plugintool.ComponentProviderAdapter;

public class FileDetailProvider extends ComponentProviderAdapter {

		private GolangAnalyzerExtensionPlugin gae_tool;
		private JPanel main_panel;

		public FileDetailProvider(GolangAnalyzerExtensionPlugin tool, String file_name) {
			super(tool.getTool(), "FileDetail", tool.getName());

			gae_tool=tool;
			main_panel=create_main_panel(file_name);

			setTitle(file_name);
			addToTool();
		}

		private JPanel create_main_panel(String file_name) {
			JPanel panel = new JPanel(new BorderLayout());
			panel.add(create_func_table(file_name));
			panel.setPreferredSize(new Dimension(900, 600));

			return panel;
		}

		private JScrollPane create_func_table(String file_name) {
			if(gae_tool==null) {
				return new JScrollPane();
			}

			String[] columns={"Line", "FuncName"};
			Map<Long, String> line_func_map = new HashMap<>();
			for(GolangFunction func : gae_tool.get_function_list()) {
				for(FileLine file_line : func.get_file_line_comment_map().values()) {
					if(file_line.get_file_name().equals(file_name)) {
						line_func_map.put(file_line.get_line_num(), func.get_func_name());
					}
				}
			}
			Object[] map_key=line_func_map.keySet().toArray();
	        Arrays.sort(map_key);
			Object[][] data=new Object[line_func_map.size()][2];
			int i=0;
			for(Object key : map_key) {
				Object[] row={key, line_func_map.get(key)};
				data[i++]=row;
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