package golanganalyzerextension;

import java.util.List;


public class AnalyzedInfoContainer {
	private static AnalyzedInfoContainer instance=new AnalyzedInfoContainer();
	List<GolangFunction> func_list=null;

	private AnalyzedInfoContainer() {
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
}
