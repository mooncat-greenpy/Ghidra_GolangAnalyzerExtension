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
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;
import resources.ResourceManager;

import golanganalyzerextension.log.Logger;


public class FuncNameGuesser {
	private static String PATTERN_FILE = "golang.mv.db";

	private Program program;
	private FunctionDatabase database;

	public FuncNameGuesser(Program program) {
		this.program = program;
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

	public void remove_match_mistakes(Map<Address, String> func_name_map) {
		Map<String, Integer> freq_map = new HashMap<>();
		for (String value : func_name_map.values()) {
			freq_map.put(value, freq_map.getOrDefault(value, 0) + 1);
		}
		Iterator<Map.Entry<Address, String>> func_name_map_itr = func_name_map.entrySet().iterator();
		while (func_name_map_itr.hasNext()) {
			Map.Entry<Address, String> entry = func_name_map_itr.next();
			String value = entry.getValue();
			if (freq_map.get(value) > 1) {
				func_name_map_itr.remove();
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

		double SIMILARITY_BOUND = Double.parseDouble("0.8");
		int MAXIMUM_BSIM_MATCHES_PER_FUNCTION = 10000;
		double CONFIDENCE_BOUND = 0.0;
		query.max = MAXIMUM_BSIM_MATCHES_PER_FUNCTION;
		query.thresh = SIMILARITY_BOUND;
		query.signifthresh = CONFIDENCE_BOUND;
		return query;
	}

	public Map<Address, String> guess_function_names() {
		Map<Address, String> func_name_map = new HashMap<>();
		if (database == null) {
			return func_name_map;
		}
		try {
			GenSignatures gensig = create_gen_signatures();
			QueryNearest query = create_query(gensig);

			ResponseNearest response = query.execute(database);
			if (response == null) {
				return func_name_map;
			}

			Iterator<SimilarityResult> sim_result_itr = response.result.iterator();
			while (sim_result_itr.hasNext()) {
				SimilarityResult sim_rsult = sim_result_itr.next();
				Map.Entry<Address, String> match_func = judge_func(sim_rsult);

				if (match_func != null) {
					func_name_map.put(match_func.getKey(), match_func.getValue());
				}
			}

			remove_match_mistakes(func_name_map);
		} catch(Exception e) {
			Logger.append_message(String.format("Failed to guess function names: message=%s", e.getMessage()));
		}

		return func_name_map;
	}

	private Function get_function(Address addr) {
		return program.getFunctionManager().getFunctionAt(addr);
	}

	// TODO: Fix
	// Parser -> Modifier
	// Guesser -> Modifier
	public void rename_func_for_guess(Map<Address, String> func_name_map) {
		for (Map.Entry<Address, String> entry : func_name_map.entrySet()) {
			Function func = get_function(entry.getKey());
			if (func == null) {
				continue;
			}
			try {
				func.setName(entry.getValue(), SourceType.USER_DEFINED);
			}catch(Exception e) {
				Logger.append_message(String.format("Failed to set function name: addr=%s, message=%s", entry.getKey(), e.getMessage()));
			}
		}
	}
}
