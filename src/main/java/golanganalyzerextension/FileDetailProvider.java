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

		private void add_line_func(String file_name, GolangFunction func, Map<Long, String> line_func_map) {
			Map<Integer, FileLine> file_line_map=func.get_file_line_comment_map();
			if(!file_line_map.containsKey(0) || !file_name.equals(file_line_map.get(0).get_file_name())) {
				return;
			}

			long first_line=file_line_map.get(0).get_line_num();
			long last_line=first_line;
			FileLine[] file_line_arr=file_line_map.values().toArray(new FileLine[0]);
			Arrays.sort(file_line_arr, (a, b) -> (int)a.get_line_num() - (int)b.get_line_num());
			for(FileLine file_line : file_line_arr) {
				if(!file_line.get_file_name().equals(file_name)) {
					continue;
				}
				if(file_line.get_line_num()<first_line || file_line.get_line_num()>last_line+10) {
					continue;
				}
				last_line=file_line.get_line_num()>last_line?file_line.get_line_num():last_line;
				line_func_map.put(file_line.get_line_num(), func.get_func_name());
			}
		}
		private JScrollPane create_func_table(String file_name) {
			if(gae_tool==null) {
				return new JScrollPane();
			}

			String[] columns={"Line", "FuncName"};
			Map<Long, String> line_func_map = new HashMap<>();
			for(GolangFunction func : gae_tool.get_function_list()) {
				add_line_func(file_name, func, line_func_map);
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