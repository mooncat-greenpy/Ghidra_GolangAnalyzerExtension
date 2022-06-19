package golanganalyzerextension;

import java.util.List;
import java.util.Map;

import ghidra.framework.plugintool.ServiceInfo;

//@formatter:off
@ServiceInfo (
	defaultProvider=GolangAnalyzerExtensionPlugin.class,
	description="Service to provide analyzed info"
)
//@formatter:on
public interface GolangAnalyzerExtensionService {
	public GolangBinary get_binary();
	public void store_binary(GolangBinary bin);

	public List<GolangFunction> get_function_list();
	public void store_function_list(List<GolangFunction> list);

	public List<String> get_filename_list();
	public void store_filename_list(List<String> list);
	public void add_filename(String filename);

	public Map<Long, GolangDatatype> get_datatype_map();
	public void store_datatype_map(Map<Long, GolangDatatype> map);
}
