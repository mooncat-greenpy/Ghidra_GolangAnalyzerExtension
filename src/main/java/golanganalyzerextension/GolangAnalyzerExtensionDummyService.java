package golanganalyzerextension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class GolangAnalyzerExtensionDummyService implements GolangAnalyzerExtensionService {

	GolangBinary go_bin;
	List<GolangFunction> func_list;
	List<String> filename_list;
	Map<Long, GolangDatatype> datatype_map;
	private Map<Long, String> string_map;

	public GolangAnalyzerExtensionDummyService() {
		go_bin=null;
		func_list=new ArrayList<>();
		filename_list=new ArrayList<>();
		datatype_map=new HashMap<>();
		string_map=new HashMap<>();
	}

	@Override
	public GolangBinary get_binary() {
		return go_bin;
	}

	@Override
	public void store_binary(GolangBinary bin) {
		go_bin=bin;
	}

	@Override
	public List<GolangFunction> get_function_list() {
		return func_list;
	}

	@Override
	public void store_function_list(List<GolangFunction> list) {
		func_list=list;
	}

	@Override
	public List<String> get_filename_list() {
		return filename_list;
	}

	@Override
	public void store_filename_list(List<String> list) {
		filename_list=list;
	}

	@Override
	public void add_filename(String filename) {
		if(filename_list.contains(filename)) {
			return;
		}
		filename_list.add(filename);
	}
	@Override
	public Map<Long, GolangDatatype> get_datatype_map() {
		return datatype_map;
	}

	@Override
	public void store_datatype_map(Map<Long, GolangDatatype> map) {
		datatype_map=map;
	}

	@Override
	public Map<Long, String> get_string_map() {
		return string_map;
	}

	@Override
	public void store_string_map(Map<Long, String> map) {
		string_map=map;
	}
}