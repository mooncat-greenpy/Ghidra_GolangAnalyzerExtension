package golanganalyzerextension.viewer;

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
import ghidra.program.model.symbol.Reference;
import golanganalyzerextension.function.FileLine;
import golanganalyzerextension.function.GolangFunction;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.service.GolangAnalyzerExtensionPlugin;

class FileDetailProvider extends ComponentProviderAdapter {

		private GolangAnalyzerExtensionPlugin gae_tool;
		private JPanel main_panel;

		FileDetailProvider(GolangAnalyzerExtensionPlugin tool, String file_name) {
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

			long key=0;
			for(FileLine file_line : file_line_map.values()) {
				if(file_line.get_file_name().equals(file_name)) {
					key=file_line.get_line_num();
				}
				if(line_fl_map.containsKey(key)) {
					line_fl_map.get(key).add(file_line);
				} else {
					line_fl_map.put(key, new ArrayList<>());
					line_fl_map.get(key).add(file_line);
				}
			}
		}

		private JScrollPane create_func_table(String file_name) {
			if(gae_tool==null) {
				return new JScrollPane();
			}
			GolangBinary go_bin=gae_tool.get_binary();
			if(go_bin==null) {
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
					Function func=go_bin.get_function(file_line.get_func_addr());
					String func_name=String.format("FUN_%x", file_line.get_func_addr().getOffset());
					if(func!=null) {
						func_name=func.getName();
					}
					if(!file_line.get_file_name().equals(file_name)) {
						func_name+=String.format(" ( %s )", file_line.get_file_name());
					}

					String call_info="";
					Address file_line_addr=go_bin.get_address(file_line.get_func_addr(), file_line.get_offset());
					Instruction inst=go_bin.get_instruction(file_line_addr);
					while(inst!=null && inst.getAddress().getOffset()<file_line_addr.getOffset()+file_line.get_size()) {
						for(int i=0; i<inst.getNumOperands(); i++) {
							// TODO: parse args
							for(Reference ref : inst.getOperandReferences(i)) {
								Address ref_addr=ref.getToAddress();
								Function called_func=go_bin.get_function(ref_addr);
								if(called_func==null || call_info.contains(called_func.getName())) {
									continue;
								}
								call_info+=String.format("[addr %s] ", called_func.getName());
							}
						}
						if(inst.getFlowType().isCall()) {
							for(Address called : inst.getFlows()) {
								Function called_func=go_bin.get_function(called);
								String called_func_name=String.format("FUN_%x", called.getOffset());
								if(called_func!=null) {
									called_func_name=called_func.getName();
								}
								call_info+=String.format("[call %s] ", called_func_name);
							}
						}
						inst=inst.getNext();
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