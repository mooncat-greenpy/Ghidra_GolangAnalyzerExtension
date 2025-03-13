package golanganalyzerextension.guess;

import java.io.BufferedReader;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Program;
import resources.ResourceManager;

class FuncInfo {
	private long addr;
	private String name;
	private String file_line;
	private List<String> calling;

	FuncInfo(long addr, String name, String file_line, List<String> calling) {
		this.addr = addr;
		this.name = name;
		this.file_line = file_line;
		this.calling = calling;
	}

	public long get_addr() {
		return addr;
	}

	public String get_name() {
		return name;
	}

	public String get_file_line() {
		return file_line;
	}

	public List<String> get_calling() {
		return calling;
	}
}

public class CallingFuncNameResource {
	private static int CALLING_NUM_THRESHOLD = 3;

	private List<FuncInfo> func_info_list;

	public CallingFuncNameResource(String file_name) {
		func_info_list = parse_calling_func_file(file_name);
	}

	public FuncInfo get_func_info_by_addr(long addr) {
		for (FuncInfo info : func_info_list) {
			if (info.get_addr() == addr) {
				return info;
			}
		}
		return null;
	}

	public FuncInfo get_func_info_by_file_line(String file_line) {
		FuncInfo ret = null;
		for (FuncInfo info : func_info_list) {
			if (!file_line.contains(info.get_file_line())) {
				continue;
			}
			if (ret != null) {
				return null;
			}
			ret = info;
		}
		return ret;
	}

	public List<List<String>> get_calling_func_name_lists(String name) {
		List<List<String>> ret = new LinkedList<>();
		for (FuncInfo info : func_info_list) {
			if (info.get_name().equals(name)) {
				ret.add(info.get_calling());
			}
		}
		return ret;
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

	public void guess_func_name_by_file_line(Program program, FunctionIterator itr, Map<Address, String> guessed_map) {
		while (itr.hasNext()) {
			Function func = itr.next();
			Address addr = func.getEntryPoint();
			String comment = program.getListing().getComment(ghidra.program.model.listing.CodeUnit.PRE_COMMENT, addr);
			if (comment == null) {
				continue;
			}
			FuncInfo info = get_func_info_by_file_line(comment);
			if (info == null) {
				continue;
			}
			guessed_map.put(addr, info.get_name());
		}
	}

	public void get_func_name_by_placement(FunctionIterator itr, Map<Address, String> guessed_map) {
		Map<Address, Long> guessed_info_addr_map = new HashMap<>();
		Map<Long, Address> info_guessed_addr_map = new HashMap<>();
		for (Map.Entry<Address, String> guessed_entry : guessed_map.entrySet()) {
			for (int i = 0; i < func_info_list.size(); i++) {
				if (!guessed_entry.getValue().equals(func_info_list.get(i).get_name())) {
					continue;
				}
				guessed_info_addr_map.put(guessed_entry.getKey(), func_info_list.get(i).get_addr());
				info_guessed_addr_map.put(func_info_list.get(i).get_addr(), guessed_entry.getKey());
			}
		}
		Map<Long, Integer> info_addr_idx_map = new HashMap<>();
		for (int i = 0; i < func_info_list.size(); i++) {
			info_addr_idx_map.put(func_info_list.get(i).get_addr(), i);
		}

		while (itr.hasNext()) {
			Function func = itr.next();
			Address addr = func.getEntryPoint();
			if (guessed_map.containsKey(addr)) {
				continue;
			}

			Map<Long, Integer> freq_map = new HashMap<>();
			for (Map.Entry<Address, String> guessed_entry : guessed_map.entrySet()) {
				long diff = addr.getOffset() - guessed_entry.getKey().getOffset();
				long info_addr = guessed_info_addr_map.getOrDefault(guessed_entry.getKey(), (long) -1);
				if (info_addr == -1) {
					continue;
				}
				FuncInfo matched_info = get_func_info_by_addr(info_addr + diff);
				if (matched_info == null) {
					continue;
				}
				freq_map.put(matched_info.get_addr(), freq_map.getOrDefault(matched_info.get_addr(), 0) + 1);
			}

			int count = 0;
			long freq_addr = -1;
			for (Map.Entry<Long, Integer> freq_entry : freq_map.entrySet()) {
				if (freq_entry.getValue() >= count) {
					count = freq_entry.getValue();
					freq_addr = freq_entry.getKey();
				}
			}
			if (freq_addr != -1) {
				int i = info_addr_idx_map.getOrDefault(freq_addr, -1);
				if (i == -1) {
					continue;
				}
				guessed_map.put(addr, func_info_list.get(i).get_name());
				guessed_info_addr_map.put(addr, func_info_list.get(i).get_addr());
				info_guessed_addr_map.put(func_info_list.get(i).get_addr(), addr);
			}
		}
	}

	public boolean is_reliable(Address addr, Map<Address, String> guessed_map) {
		for (int i = 0; i < func_info_list.size(); i++) {
			if (!guessed_map.get(addr).equals(func_info_list.get(i).get_name())) {
				continue;
			}
			for (int j = i - 2; j < i + 3; j++) {
				if (j < 0 || j >= func_info_list.size()) {
					continue;
				}
				long diff = func_info_list.get(j).get_addr() - func_info_list.get(i).get_addr();
				String name = guessed_map.get(addr.add(diff));
				if (name == null) {
					return false;
				}
				if (!name.equals(func_info_list.get(j).get_name())) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	public void collect_func_name_by_placement(Map<Address, String> guessed_map) {
		Map<Address, Long> guessed_info_addr_map = new HashMap<>();
		Map<Long, Address> info_guessed_addr_map = new HashMap<>();
		boolean[] mapped_arr = new boolean[func_info_list.size()];
		for (Map.Entry<Address, String> guessed_entry : guessed_map.entrySet()) {
			for (int i = 0; i < func_info_list.size(); i++) {
				if (!guessed_entry.getValue().equals(func_info_list.get(i).get_name())) {
					continue;
				}
				guessed_info_addr_map.put(guessed_entry.getKey(), func_info_list.get(i).get_addr());
				info_guessed_addr_map.put(func_info_list.get(i).get_addr(), guessed_entry.getKey());
				mapped_arr[i] = true;
			}
		}

		for (int i = 0; i < mapped_arr.length; i++) {
			if (i < 2 || i >= mapped_arr.length - 3) {
				continue;
			}
			boolean[] segment = {mapped_arr[i-2], mapped_arr[i-1], mapped_arr[i], mapped_arr[i+1], mapped_arr[i+2], mapped_arr[i+3]};
			int false_count = 0;
			int false_index = -1;
			for (int j = 0; j < segment.length; j++) {
				if (!segment[j]) {
					false_count++;
					false_index = j;
				}
			}
			if (false_count == 1 && false_index != 0 && false_index != 5) {
				int idx = i - 2 + false_index;
				long diff = func_info_list.get(idx).get_addr() - func_info_list.get(idx - 1).get_addr();
				Address addr = info_guessed_addr_map.get(func_info_list.get(idx - 1).get_addr());
				if (addr == null) {
					continue;
				}
				String matched_name = func_info_list.get(idx).get_name();
				if (matched_name == null) {
					continue;
				}
				guessed_map.put(addr.add(diff), matched_name);
				guessed_info_addr_map.put(addr, func_info_list.get(idx).get_addr());
				info_guessed_addr_map.put(func_info_list.get(idx).get_addr(), addr);
				mapped_arr[idx] = true;
			}
		}
	}

	private void parse_line(String line, List<FuncInfo> holder) {
		String[] line_split = line.split("\\|");
		if (line_split[1].isEmpty()) {
			return;
		}
		List<String> calling_func_list = new LinkedList<>();
		for (int i = 3; i < line_split.length; i++) {
			calling_func_list.add(line_split[i]);
		}
		holder.add(new FuncInfo(Long.valueOf(line_split[0], 16), line_split[1], line_split[2], calling_func_list));
	}

	private List<FuncInfo> parse_calling_func_file(String file_name) {
		List<FuncInfo> ret = new LinkedList<>();
		InputStream input_stream = ResourceManager.getResourceAsStream(file_name);
		try (InputStreamReader input_reader = new InputStreamReader(input_stream);
			BufferedReader reader = new BufferedReader(input_reader)) {
			String line;
			while ((line = reader.readLine()) != null) {
				parse_line(line, ret);
			}
		} catch (Exception e) {
		}
		return ret;
	}
}
