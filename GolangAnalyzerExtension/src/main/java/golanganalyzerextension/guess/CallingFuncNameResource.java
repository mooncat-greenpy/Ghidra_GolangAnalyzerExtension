package golanganalyzerextension.guess;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import resources.ResourceManager;

public class CallingFuncNameResource {
	private static int CALLING_NUM_THRESHOLD = 3;

	private Map<String, List<List<String>>> calling_func_map;

	public CallingFuncNameResource(String file_name) {
		calling_func_map = parse_calling_func_file(file_name);
	}

	public List<List<String>> get_calling_func_name_lists(String name) {
		if (calling_func_map == null) {
			return null;
		}
		return calling_func_map.get(name);
	}

	public List<String> get_calling_func_name_list(String name, int call_count) {
		List<List<String>> calling_name_lists = get_calling_func_name_lists(name);
		if (calling_name_lists == null) {
			return null;
		}

		List<String> calling_name_list = null;
		for (List<String> elem : calling_name_lists) {
			if (Math.abs(elem.size() - call_count) > CALLING_NUM_THRESHOLD) {
				continue;
			}
			if (calling_name_list == null) {
				calling_name_list = elem;
				continue;
			}

			if (Math.abs(elem.size() - call_count) < Math.abs(calling_name_list.size() - call_count)) {
				calling_name_list = elem;
			}
		}

		return calling_name_list;
	}

	private void parse_calling_func_line(String line, Map<String, List<List<String>>> calling_func_map) {
		String[] line_split = line.split("\\|");
		if (line_split[0].isEmpty()) {
			return;
		}
		List<String> calling_func_list = new LinkedList<>();
		for (int i = 1; i < line_split.length; i++) {
			calling_func_list.add(line_split[i]);
		}
		List<List<String>> new_calling_func = calling_func_map.getOrDefault(line_split[0], new LinkedList<>());
		new_calling_func.add(calling_func_list);
		calling_func_map.put(line_split[0], new_calling_func);
	}

	private Map<String, List<List<String>>> parse_calling_func_file(String file_name) {
		Map<String, List<List<String>>> ret = new HashMap<>();
		InputStream input_stream = ResourceManager.getResourceAsStream(file_name);
		try (InputStreamReader input_reader = new InputStreamReader(input_stream);
			BufferedReader reader = new BufferedReader(input_reader)) {
			String line;
			while ((line = reader.readLine()) != null) {
				parse_calling_func_line(line, ret);
			}
		} catch (Exception e) {
		}
		return ret;
	}

}
