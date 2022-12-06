package golanganalyzerextension;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import javax.swing.JComponent;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.Instruction;

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

		private void add_func_to_line_fl_map(String file_name, GolangFunction func, Map<Long, List<FileLine>> line_fl_map) {
			Map<Integer, FileLine> file_line_map=func.get_file_line_comment_map();
			if(!file_line_map.containsKey(0) || !file_name.equals(file_line_map.get(0).get_file_name())) {
				return;
			}

			for(FileLine file_line : file_line_map.values()) {
				if(!file_line.get_file_name().equals(file_name)) {
					continue;
				}
				if(line_fl_map.containsKey(file_line.get_line_num())) {
					line_fl_map.get(file_line.get_line_num()).add(file_line);
				} else {
					line_fl_map.put(file_line.get_line_num(), new ArrayList<>());
					line_fl_map.get(file_line.get_line_num()).add(file_line);
				}
			}
		}

		private JScrollPane create_func_table(String file_name) {
			if(gae_tool==null) {
				return new JScrollPane();
			}

			Map<Long, List<FileLine>> line_fl_map=new HashMap<>();
			for(GolangFunction func : gae_tool.get_function_list()) {
				add_func_to_line_fl_map(file_name, func, line_fl_map);
			}

			int data_count=0;
			for(Long key : line_fl_map.keySet()) {
				List<FileLine> fl=line_fl_map.get(key);
				data_count+=fl.size();
			}

			String[] columns={"Line", "FuncName", "Call"};
			Object[][] data=new Object[data_count][3];
			Object[] map_key=line_fl_map.keySet().toArray();
	        Arrays.sort(map_key);
			int idx=0;
			for(Object key : map_key) {
				for(FileLine file_line : line_fl_map.get(key)) {
					String call_info="";
					Instruction inst=gae_tool.get_binary().get_instruction(file_line.get_address());
					while(inst!=null && inst.getAddress().getOffset()<file_line.get_address().getOffset()+file_line.get_size()) {
						if(inst.getFlowType().isCall()) {
							for(Address called : inst.getFlows()) {
								// TODO: runtime.newproc
								Function called_func=gae_tool.get_binary().get_function(called);
								String called_func_name=String.format("FUN_%x", called.getOffset());
								if(called_func!=null) {
									called_func_name=called_func.getName();
								}
								call_info+=String.format("[call %s] ", called_func_name);
							}
						}
						inst=inst.getNext();
					}

					Function func=gae_tool.get_binary().get_function(file_line.get_func_addr());
					String func_name=String.format("FUN_%x", file_line.get_func_addr().getOffset());
					if(func!=null) {
						func_name=func.getName();
					}
					Object[] row={key, func_name, call_info};
					data[idx++]=row;
					if(idx>=data_count) {
						break;
					}
				}
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