package golanganalyzerextension.guess;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.net.URL;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import resources.ResourceManager;

public class CommonCallingFuncNameFile {
	private static String COMMON_CALLING_FUNC_NAME_FILE = "calling_func_name/common_calling_func.txt";

	Map<String, Map<String, List<String>>> calling_func_name_map;

	public CommonCallingFuncNameFile(String version) {
		calling_func_name_map = parse_calling_func_file(COMMON_CALLING_FUNC_NAME_FILE, version);
	}

	public List<String> get_pre_func_name_list(String func_name) {
		if (!calling_func_name_map.containsKey(func_name)) {
			return new LinkedList<>();
		}
		return calling_func_name_map.get(func_name).get("pre");
	}

	public List<String> get_post_func_name_list(String func_name) {
		if (!calling_func_name_map.containsKey(func_name)) {
			return new LinkedList<>();
		}
		return calling_func_name_map.get(func_name).get("post");
	}

	private void parse_line(String line, String version, Map<String, Map<String, List<String>>> holder) {
		if (line == null || line.isEmpty()) {
			return;
		}

		String[] parts = line.split("\\|");
		if (parts.length < 3) {
			return;
		}

		if (!parts[0].contains(version)) {
			return;
		}

		String name = parts[1];
		List<String> pre_list = new LinkedList<>();
		List<String> post_list = new LinkedList<>();

		int pre_idx = -1;
		int post_idx = -1;

		for (int i = 2; i < parts.length; i++) {
			if (parts[i].equals("pre")) {
				pre_idx = i;
			} else if (parts[i].equals("post")) {
				post_idx = i;
			}
		}

		if (pre_idx >= 0 && post_idx >= 0) {
			for (int i = pre_idx + 1; i < post_idx; i++) {
				pre_list.add(parts[i]);
			}
			for (int i = post_idx + 1; i < parts.length; i++) {
				post_list.add(parts[i]);
			}
		}

		Map<String, List<String>> pre_post_map = new HashMap<>();
		pre_post_map.put("pre", pre_list);
		pre_post_map.put("post", post_list);

		holder.put(name, pre_post_map);
	}

	private Map<String, Map<String, List<String>>> parse_calling_func_file(String file_name, String version) {
		Map<String, Map<String, List<String>>> ret = new HashMap<>();
		URL url = ResourceManager.getResource(file_name);
		if (url == null) {
			return ret;
		}
		try (InputStream in = url.openStream()) {
			try (InputStreamReader input_reader = new InputStreamReader(in);
				BufferedReader reader = new BufferedReader(input_reader)) {
				String line;
				while ((line = reader.readLine()) != null) {
					parse_line(line, version, ret);
				}
			}
		} catch (Exception e) {
		}
		return ret;
	}
}
