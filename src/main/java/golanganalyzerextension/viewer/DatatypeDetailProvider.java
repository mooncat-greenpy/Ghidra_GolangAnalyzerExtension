package golanganalyzerextension.viewer;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.GridLayout;
import java.util.List;
import java.util.Optional;

import javax.swing.BorderFactory;
import javax.swing.JComponent;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTable;

import ghidra.framework.plugintool.ComponentProviderAdapter;
import ghidra.program.model.data.DataTypeComponent;
import ghidra.program.model.data.StructureDataType;
import ghidra.util.layout.VerticalLayout;
import golanganalyzerextension.datatype.GolangDatatype;
import golanganalyzerextension.datatype.UncommonType;
import golanganalyzerextension.datatype.UncommonType.UncommonMethod;
import golanganalyzerextension.service.GolangAnalyzerExtensionPlugin;

class DatatypeDetailProvider extends ComponentProviderAdapter {

	private GolangAnalyzerExtensionPlugin gae_tool;
	private JPanel main_panel;

	DatatypeDetailProvider(GolangAnalyzerExtensionPlugin tool, GolangDatatype go_datatype) {
		super(tool.getTool(), "DatatypeDetail", tool.getName());

		gae_tool=tool;
		main_panel=create_main_panel(go_datatype);

		setTitle(go_datatype.get_name());
		addToTool();
	}

	private JPanel create_main_panel(GolangDatatype go_datatype) {
		JPanel panel = new JPanel(new BorderLayout());
		panel.add(create_info_panel(go_datatype), BorderLayout.WEST);

		JPanel table_panel=new JPanel(new GridLayout(2, 1));
		table_panel.add(create_datatype_table(go_datatype));
		table_panel.add(create_uncommon_table(go_datatype));
		panel.add(table_panel, BorderLayout.CENTER);
		panel.setPreferredSize(new Dimension(900, 600));

		return panel;
	}

	private JPanel create_info_panel(GolangDatatype go_datatype) {
		JPanel panel = new JPanel(new VerticalLayout(0));
		panel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

		JLabel name_panel=new JLabel(String.format("Name: %s", go_datatype.get_name()));
		name_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
		panel.add(name_panel);
		JLabel go_version_panel=new JLabel(String.format("Type: %s", go_datatype.get_kind().name()));
		go_version_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
		panel.add(go_version_panel);
		JLabel pointer_size_panel=new JLabel(String.format("Size: %d", go_datatype.get_size()));
		pointer_size_panel.setBorder(BorderFactory.createEmptyBorder(5,5,5,5));
		panel.add(pointer_size_panel);

		return panel;
	}

	private JScrollPane create_datatype_table(GolangDatatype go_datatype) {		
		if(gae_tool==null) {
			return new JScrollPane();
		}

		String[] columns={"Offset", "Datatype", "Name", "Comment", "Length"};
		StructureDataType datatype=go_datatype.get_datatype();
		Object[][] data=new Object[datatype.getNumComponents()][5];
		for(int i=0; i<datatype.getNumComponents(); i++) {
			DataTypeComponent dtc=datatype.getComponent(i);
			if(dtc==null) {
				Object[] row={0, "Null", "Null", "Null", 0};
				data[i]=row;
			} else {
				Object[] row={dtc.getOffset(), dtc.getDataType().getName(), dtc.getFieldName(), dtc.getComment(), dtc.getLength()};
				data[i]=row;
			}
		}

		JTable table=new JTable(data, columns);
		table.setEnabled(false);
	    return new JScrollPane(table);
	}

	private JScrollPane create_uncommon_table(GolangDatatype go_datatype) {
		Optional<UncommonType> uncommon_type_opt=go_datatype.get_uncommon_type();

		String[] columns={"Method name", "Method type", "Ifn", "Tfn"};
		Object[][] data;
		if(uncommon_type_opt.isEmpty()) {
			data=new Object[0][4];
		} else {
			UncommonType uncommon_type=uncommon_type_opt.get();
			List<UncommonMethod> uncommon_method_list=uncommon_type.get_method_list();
			data=new Object[uncommon_method_list.size()][4];
			for(int i=0; i<uncommon_method_list.size(); i++) {
				UncommonMethod method=uncommon_method_list.get(i);
				GolangDatatype datatype=gae_tool.get_datatype_map().get(method.get_type_offset());
				String mtyp_str="";
				if(datatype!=null) {
					mtyp_str=datatype.get_name();
				}
				Object[] row={
					method.get_name(),
					mtyp_str,
					String.format("%x", method.get_interface_method_addr().getOffset()),
					String.format("%x", method.get_normal_method_addr().getOffset())
				};
				data[i]=row;
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
