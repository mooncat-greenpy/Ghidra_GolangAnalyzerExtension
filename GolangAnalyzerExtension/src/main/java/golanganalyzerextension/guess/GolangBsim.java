package golanganalyzerextension.guess;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.Arrays;
import java.util.Comparator;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.TreeSet;

import ghidra.features.bsim.gui.search.results.BSimMatchResult;
import ghidra.features.bsim.gui.search.results.ExecutableResult;
import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.facade.*;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.protocol.BSimFilter;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

import golanganalyzerextension.log.Logger;
import golanganalyzerextension.version.GolangVersion;

public class GolangBsim {

	private static String PATTERN_FILE = "golang.mv.db";
	private static int IS_GOLANG_FUNC_NUM_THRESHOLD = 200;

	private static final double SIMILARITY_BOUND = 0.8;
	private static final int MAX_NUM_FUNCTIONS = 10000;
	private static final double SIGNIFICANCE_BOUND = 0.0;

	private Program program;

	public FunctionDatabase database;

	private GolangVersion go_version;
	private String os;
	private String arch;

	public GolangBsim(Program program) {
		this.program=program;
		go_version = null;
		os = null;
		arch = null;

		init_database();
		return;
	}

	public GolangVersion get_go_version() {
		return go_version;
	}

	public String get_os() {
		return os;
	}

	public String get_arch() {
		return arch;
	}

	private HashSet<FunctionSymbol> get_functions_to_query(Program program) {
		HashSet<FunctionSymbol> functions = new HashSet<>();
		FunctionIterator itr = program.getFunctionManager().getFunctionsNoStubs(true);
		for (Function func : itr) {
			functions.add((FunctionSymbol) func.getSymbol());
		}
		return functions;
	}

	private List<SimilarityResult> execute_query(SimilarFunctionQueryService query_service, SFQueryInfo info)
			throws QueryDatabaseException, CancelledException {

		SFQueryResult query_results = query_service.querySimilarFunctions(info, null, TaskMonitor.DUMMY);
		return query_results.getSimilarityResults();
	}

	private SimilarFunctionQueryService init_query_service() {
		SimilarFunctionQueryService query_service = new SimilarFunctionQueryService(program);
		Path temp_path = null;
		try {
			temp_path = create_resource_temp_file(PATTERN_FILE);
			if (temp_path == null) {
				Logger.append_message("Failed to get database resource");
				return null;
			}

			URL url = temp_path.toFile().toURI().toURL();

			query_service.initializeDatabase(url.toString());
			FunctionDatabase.BSimError error = query_service.getLastError();// FunctionDatabase.Error (ghidra 11.2.1)
			if (error != null && error.category == ErrorCategory.Nodatabase) {
				Logger.append_message("Failed to find database: url=" + url.toString());
				return null;
			}
		}
		catch (Exception e) {
			Logger.append_message("Failed to initialize query service: message=" + e.getMessage());
			return null;
		}
		return query_service;
	}

	private void guess_function_names(List<SimilarityResult> sim_result_list, GuessedFuncNames guessed_names_holder) {
		try {
			for (SimilarityResult sim_rsult : sim_result_list) {
				Map.Entry<Address, String> match_func = judge_func(sim_rsult);

				if (match_func != null) {
					guessed_names_holder.put(match_func.getKey(), match_func.getValue(), GuessedConfidence.LOW);
				}
			}

			remove_match_mistakes(guessed_names_holder);

			if (guessed_names_holder.size() > IS_GOLANG_FUNC_NUM_THRESHOLD) {
				return;
			}
		} catch(Exception e) {
			Logger.append_message(String.format("Failed to guess function names: message=%s", e.getMessage()));
		}
	}

	private void guess_golang_version(List<BSimMatchResult> bsim_result_list) {
		TreeSet<ExecutableResult> execrows = ExecutableResult.generateFromMatchRows(bsim_result_list);
		ExecutableResult[] results = new ExecutableResult[execrows.size()];
		results = execrows.toArray(results);

		Arrays.sort(results, new Comparator<ExecutableResult>() {
			@Override
			public int compare(ExecutableResult o1, ExecutableResult o2) {
				return Double.compare(o2.getSignificanceSum(), o1.getSignificanceSum());
			}
		});

		String exec = "";
		double score = 0;
		for (int i = 0; i < results.length; ++i) {
			if (results[i].getSignificanceSum() > score) {
				exec = results[i].getExecutableRecord().getNameExec();
				score = results[i].getSignificanceSum();
			}
		}

		String[] exec_split = exec.split("_");
		if (exec_split.length < 3) {
			return;
		}
		os = exec_split[exec_split.length - 3];
		arch = exec_split[exec_split.length - 2];
		go_version = new GolangVersion(exec_split[exec_split.length - 1]);
	}

	public void guess(GuessedFuncNames guessed_names_holder) {
		SimilarFunctionQueryService query_service = init_query_service();

		HashSet<FunctionSymbol> funcs_to_query = get_functions_to_query(program);
		SFQueryInfo query_info = new SFQueryInfo(funcs_to_query);
		BSimFilter bsim_filter = query_info.getBsimFilter();

		query_info.setMaximumResults(MAX_NUM_FUNCTIONS);
		query_info.setSimilarityThreshold(SIMILARITY_BOUND);
		query_info.setSignificanceThreshold(SIGNIFICANCE_BOUND);

		List<SimilarityResult> sim_result_list;
		try {
			sim_result_list = execute_query(query_service, query_info);
		} catch (Exception e) {
			return;
		}
		List<BSimMatchResult> bsim_result_list = BSimMatchResult.generate(sim_result_list, program);
		guess_golang_version(bsim_result_list);
		guess_function_names(sim_result_list, guessed_names_holder);
	}

	private void init_database() {
		Path temp_path = null;
		try {
			temp_path = create_resource_temp_file(PATTERN_FILE);
			if (temp_path == null) {
				Logger.append_message("Failed to get database resource");
				return;
			}

			URL url = temp_path.toFile().toURI().toURL();
			URL bsim_url = BSimClientFactory.deriveBSimURL(url.toString());
			if (bsim_url == null) {
				Logger.append_message("Failed to get database");
				return;
			}
			FunctionDatabase database = BSimClientFactory.buildClient(bsim_url, false);
			if (database.initialize()) {
				this.database = database;
			} else {
				this.database = null;
				Logger.append_message("Failed to initialize database");
			}
		} catch(Exception e) {
			Logger.append_message(String.format("Failed to setup FuncNameGuesser: message=%s", e.getMessage()));
		} finally {
			try {
				Files.deleteIfExists(temp_path);
			} catch(Exception e) {
			}
		}
	}

	private Path create_resource_temp_file(String name) {
		try {
			URL url = ResourceManager.getResource(name);
			if (url == null) {
				return null;
			}
			try (InputStream in = url.openStream()) {
				Path temp_path = Files.createTempFile("tempfile", ".mv.db");
				temp_path.toFile().deleteOnExit();
				try (OutputStream out_stream = new FileOutputStream(temp_path.toFile())) {
					byte[] buffer = new byte[1024];
					int length;
					while ((length = in.read(buffer)) > 0) {
						out_stream.write(buffer, 0, length);
					}
				}
				return temp_path;
			}
		} catch (Exception e) {
			return null;
		}
	}

	private Map.Entry<Address, String> judge_func(SimilarityResult sim_rsult) {
		FunctionDescription orig_func_desc = sim_rsult.getBase();
		Iterator<SimilarityNote> sim_note_itr = sim_rsult.iterator();

		String match_func_name = "";
		while (sim_note_itr.hasNext()) {
			SimilarityNote sim_note = sim_note_itr.next();
			FunctionDescription func_desc = sim_note.getFunctionDescription();
			String func_name = func_desc.getFunctionName().replace("�", "_");
			if (func_name.contains("::")) {
				func_name = func_name.split("::")[1];
			}

			if (match_func_name.isEmpty()) {
				match_func_name = func_name;
			} else if (!match_func_name.equals(func_name)) {
				return null;
			}
		}
		if (match_func_name.isEmpty()) {
			return null;
		}

		try {
			Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(orig_func_desc.getAddress());
			return new AbstractMap.SimpleEntry<Address, String>(addr, match_func_name);
		}catch(AddressOutOfBoundsException e) {
			return null;
		}
	}

	private void remove_match_mistakes(GuessedFuncNames func_name_map) {
		Map<String, Integer> freq_map = new HashMap<>();
		for (Address addr : func_name_map.keys()) {
			String value = func_name_map.get_name(addr);
			freq_map.put(value, freq_map.getOrDefault(value, 0) + 1);
		}
		for (GuessedName guessed_name : func_name_map.guessed_names()) {
			String value = guessed_name.get_name();
			if (freq_map.get(value) > 1) {
				func_name_map.remove(guessed_name.get_addr());
			}
		}
	}
}
