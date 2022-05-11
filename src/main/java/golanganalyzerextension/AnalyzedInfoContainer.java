package golanganalyzerextension;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;


public class AnalyzedInfoContainer {
	private static AnalyzedInfoContainer instance=new AnalyzedInfoContainer();
	List<GolangFunction> func_list=null;
	Map<Long, GolangDatatype> datatype_map=null;

	private AnalyzedInfoContainer() {
		func_list=new ArrayList<>();
		datatype_map=new HashMap<>();
	}

	public static AnalyzedInfoContainer getInstance() {
		return instance;
	}

	public void storeFunctionList(List<GolangFunction> list) {
		func_list=list;
	}

	public List<GolangFunction> getFunctionList() {
		return func_list;
	}	

	public void storeDatatypeMap(Map<Long, GolangDatatype> map) {
		datatype_map=map;
	}

	public Map<Long, GolangDatatype> getDatatypeMap() {
		return datatype_map;
	}
}
