package golanganalyzerextension.guess;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.AbstractMap;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Iterator;
import java.util.Map;
import java.util.Set;

import ghidra.features.bsim.query.BSimClientFactory;
import ghidra.features.bsim.query.description.FunctionDescription;
import ghidra.features.bsim.query.description.ExecutableRecord;
import ghidra.features.bsim.query.facade.FunctionSymbolIterator;
import ghidra.features.bsim.query.FunctionDatabase;
import ghidra.features.bsim.query.GenSignatures;
import ghidra.features.bsim.query.protocol.QueryNearest;
import ghidra.features.bsim.query.protocol.ResponseNearest;
import ghidra.features.bsim.query.protocol.SimilarityNote;
import ghidra.features.bsim.query.protocol.SimilarityResult;
import ghidra.program.database.symbol.FunctionSymbol;
import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressOutOfBoundsException;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

import golanganalyzerextension.log.Logger;
import golanganalyzerextension.version.GolangVersion;

public class GolangBsim {

	private static String PATTERN_FILE = "golang.mv.db";
	private static int IS_GOLANG_FUNC_NUM_THRESHOLD = 200;

	private static double SIMILARITY_BOUND = 0.8;
	private static int MAXIMUM_BSIM_MATCHES_PER_FUNCTION = 10000;
	private static double CONFIDENCE_BOUND = 0.0;

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

	public void guess(GuessedFuncNames guessed_names_holder) {
		ResponseNearest response = execute_bsim();
		if (response == null) {
			return;
		}

		guess_golang_version(response.result.iterator());
		guess_function_names(response.result.iterator(), guessed_names_holder);
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
			Path temp_path = Files.createTempFile("tempfile", ".mv.db");
			temp_path.toFile().deleteOnExit();

			InputStream in_stream = ResourceManager.getResourceAsStream(PATTERN_FILE);
			try (OutputStream out_stream = new FileOutputStream(temp_path.toFile())) {
				byte[] buffer = new byte[1024];
				int length;
				while ((length = in_stream.read(buffer)) > 0) {
					out_stream.write(buffer, 0, length);
				}
			}
			return temp_path;
		} catch (Exception e) {
			return null;
		}
	}

	private Set<FunctionSymbol> get_func_syms() {
		Set<FunctionSymbol> funcs = new HashSet<>();
		FunctionIterator itr = program.getListing().getFunctions(true);
		while (itr.hasNext()) {
			Function func = itr.next();
			funcs.add((FunctionSymbol) func.getSymbol());
		}
		return funcs;
	}

	private Map.Entry<Address, String> judge_func(SimilarityResult sim_rsult) {
		FunctionDescription orig_func_desc = sim_rsult.getBase();
		Iterator<SimilarityNote> sim_note_itr = sim_rsult.iterator();

		String match_func_name = "";
		while (sim_note_itr.hasNext()) {
			SimilarityNote sim_note = sim_note_itr.next();
			FunctionDescription func_desc = sim_note.getFunctionDescription();
			String func_name = func_desc.getFunctionName();
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

	private GenSignatures create_gen_signatures() throws Exception {
		GenSignatures gensig = new GenSignatures(false);
		gensig.setVectorFactory(database.getLSHVectorFactory());
		gensig.openProgram(program, null, null, null, null, null);

		Set<FunctionSymbol> funcs = get_func_syms();
		FunctionSymbolIterator itr = new FunctionSymbolIterator(funcs.iterator());
		int count = funcs.size();
		gensig.scanFunctions(itr, count, TaskMonitor.DUMMY);
		return gensig;
	}

	private QueryNearest create_query(GenSignatures gensig) throws Exception {
		QueryNearest query = new QueryNearest();
		query.manage = gensig.getDescriptionManager();

		query.max = MAXIMUM_BSIM_MATCHES_PER_FUNCTION;
		query.thresh = SIMILARITY_BOUND;
		query.signifthresh = CONFIDENCE_BOUND;
		return query;
	}

	private void guess_golang_version(Iterator<SimilarityResult> sim_result_itr) {
		Map<String, Double> exec_score = new HashMap<>();
		while (sim_result_itr.hasNext()) {
			SimilarityResult sim_rsult = sim_result_itr.next();

			Iterator<SimilarityNote> sim_note_itr = sim_rsult.iterator();
			while (sim_note_itr.hasNext()) {
				SimilarityNote sim_note = sim_note_itr.next();
				FunctionDescription func_desc = sim_note.getFunctionDescription();
				ExecutableRecord exec_record = func_desc.getExecutableRecord();
				String exec = exec_record.getNameExec();
				double score = sim_note.getSignificance();
				exec_score.put(exec, exec_score.getOrDefault(exec, 0.0) + score);
			}
		}

		String exec = "";
		double score = 0;
		for (Map.Entry<String, Double> entry : exec_score.entrySet()) {
			if (entry.getValue() > score) {
				exec = entry.getKey();
				score = entry.getValue();
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

	private ResponseNearest execute_bsim() {
		if (database == null) {
			return null;
		}
		try {
			GenSignatures gensig = create_gen_signatures();
			QueryNearest query = create_query(gensig);

			return query.execute(database);
		} catch(Exception e) {
			Logger.append_message(String.format("Failed to execute bsim: message=%s", e.getMessage()));
		}
		return null;
	}

	private void guess_function_names(Iterator<SimilarityResult> sim_result_itr, GuessedFuncNames guessed_names_holder) {
		try {
			while (sim_result_itr.hasNext()) {
				SimilarityResult sim_rsult = sim_result_itr.next();
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
}
