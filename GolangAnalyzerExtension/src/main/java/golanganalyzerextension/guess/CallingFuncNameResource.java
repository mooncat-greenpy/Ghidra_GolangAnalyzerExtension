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

class CallingFuncInfo {
	private long addr;
	private String name;
	private String file_line;
	private List<String> pre;
	private List<String> post;
	private List<String> calling;

	CallingFuncInfo(long addr, String name, String file_line, List<String> pre, List<String> post, List<String> calling) {
		this.addr = addr;
		this.name = name;
		this.file_line = file_line;
		this.pre = pre;
		this.post = post;
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

	public List<String> get_pre() {
		return pre;
	}

	public List<String> get_post() {
		return post;
	}

	public List<String> get_calling() {
		return calling;
	}
}

public class CallingFuncNameResource {
	private static String CALLING_FUNC_NAME_FILE_FORMAT = "calling_func_name/%s_%s_%s.txt";
	private static int CALLING_NUM_THRESHOLD = 3;

	private CommonCallingFuncNameFile common_file;
	private List<CallingFuncInfo> calling_func_info_list;

	public CallingFuncNameResource(String os, String arch, String version) {
		common_file = new CommonCallingFuncNameFile(version);
		calling_func_info_list = parse_calling_func_file(String.format(CALLING_FUNC_NAME_FILE_FORMAT, os, arch, version));
	}

	public CallingFuncInfo get_func_info_by_addr(long addr) {
		for (CallingFuncInfo info : calling_func_info_list) {
			if (info.get_addr() == addr) {
				return info;
			}
		}
		return null;
	}

	public CallingFuncInfo get_func_info_by_file_line(String file_line) {
		CallingFuncInfo ret = null;
		for (CallingFuncInfo info : calling_func_info_list) {
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

	public List<CallingFuncInfo> get_calling_func_info_list(GuessedName name) {
		List<CallingFuncInfo> ret = new LinkedList<>();
		for (CallingFuncInfo info : calling_func_info_list) {
			if (info.get_name().equals(name.get_name())) {
				ret.add(info);
			}
		}
		return ret;
	}

	public CallingFuncInfo get_calling_func_info_list(GuessedName name, int call_count) {
		List<CallingFuncInfo> info_list = get_calling_func_info_list(name);
		if (info_list == null) {
			return null;
		}

		CallingFuncInfo ret = null;
		for (CallingFuncInfo info : info_list) {
			List<String> calling = info.get_calling();
			if (Math.abs(calling.size() - call_count) > CALLING_NUM_THRESHOLD + (name.get_confidence().priority() == GuessedConfidence.VERY_HIGH.priority() ? 1 : 0)) {
				continue;
			}
			if (ret == null) {
				ret = info;
				continue;
			}

			if (Math.abs(calling.size() - call_count) < Math.abs(ret.get_calling().size() - call_count)) {
				ret = info;
			}
		}

		return ret;
	}

	public void guess_func_name_by_file_line(Program program, FunctionIterator itr, GuessedFuncNames guessed_names_holder) {
		while (itr.hasNext()) {
			Function func = itr.next();
			Address addr = func.getEntryPoint();
			String comment = program.getListing().getComment(ghidra.program.model.listing.CodeUnit.PRE_COMMENT, addr);
			if (comment == null) {
				continue;
			}
			CallingFuncInfo info = get_func_info_by_file_line(comment);
			if (info == null) {
				continue;
			}
			guessed_names_holder.put(addr, info.get_name(), GuessedConfidence.HIGH);
		}
	}

	public void get_func_name_by_placement(FunctionIterator itr, GuessedFuncNames guessed_names_holder) {
		Map<Address, Long> guessed_info_addr_map = new HashMap<>();
		Map<Long, Address> info_guessed_addr_map = new HashMap<>();
		for (GuessedName guessed_name : guessed_names_holder.guessed_names()) {
			for (int i = 0; i < calling_func_info_list.size(); i++) {
				if (!guessed_name.get_name().equals(calling_func_info_list.get(i).get_name())) {
					continue;
				}
				guessed_info_addr_map.put(guessed_name.get_addr(), calling_func_info_list.get(i).get_addr());
				info_guessed_addr_map.put(calling_func_info_list.get(i).get_addr(), guessed_name.get_addr());
			}
		}
		Map<Long, Integer> info_addr_idx_map = new HashMap<>();
		for (int i = 0; i < calling_func_info_list.size(); i++) {
			info_addr_idx_map.put(calling_func_info_list.get(i).get_addr(), i);
		}

		while (itr.hasNext()) {
			Function func = itr.next();
			Address addr = func.getEntryPoint();
			if (guessed_names_holder.get_name(addr) != null) {
				continue;
			}

			Map<Long, Integer> freq_map = new HashMap<>();
			for (GuessedName guessed_name : guessed_names_holder.guessed_names()) {
				long diff = addr.getOffset() - guessed_name.get_addr().getOffset();
				long info_addr = guessed_info_addr_map.getOrDefault(guessed_name.get_addr(), (long) -1);
				if (info_addr == -1) {
					continue;
				}
				CallingFuncInfo matched_info = get_func_info_by_addr(info_addr + diff);
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
				guessed_names_holder.put(addr, calling_func_info_list.get(i).get_name(), GuessedConfidence.LOW);
				guessed_info_addr_map.put(addr, calling_func_info_list.get(i).get_addr());
				info_guessed_addr_map.put(calling_func_info_list.get(i).get_addr(), addr);
			}
		}
	}

	public boolean is_reliable(Address addr, GuessedFuncNames guessed_names_holder) {
		for (int i = 0; i < calling_func_info_list.size(); i++) {
			if (!guessed_names_holder.get_name(addr).equals(calling_func_info_list.get(i).get_name())) {
				continue;
			}
			for (int j = i - 2; j < i + 3; j++) {
				if (j < 0 || j >= calling_func_info_list.size()) {
					continue;
				}
				long diff = calling_func_info_list.get(j).get_addr() - calling_func_info_list.get(i).get_addr();
				String name = guessed_names_holder.get_name(addr.add(diff));
				if (name == null) {
					return false;
				}
				if (!name.equals(calling_func_info_list.get(j).get_name())) {
					return false;
				}
			}
			return true;
		}
		return false;
	}

	public void collect_func_name_by_placement(GuessedFuncNames guessed_names_holder) {
		Map<Address, Long> guessed_info_addr_map = new HashMap<>();
		Map<Long, Address> info_guessed_addr_map = new HashMap<>();
		boolean[] mapped_arr = new boolean[calling_func_info_list.size()];
		for (GuessedName guessed_name : guessed_names_holder.guessed_names()) {
			for (int i = 0; i < calling_func_info_list.size(); i++) {
				if (!guessed_name.get_name().equals(calling_func_info_list.get(i).get_name())) {
					continue;
				}
				guessed_info_addr_map.put(guessed_name.get_addr(), calling_func_info_list.get(i).get_addr());
				info_guessed_addr_map.put(calling_func_info_list.get(i).get_addr(), guessed_name.get_addr());
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
				long diff = calling_func_info_list.get(idx).get_addr() - calling_func_info_list.get(idx - 1).get_addr();
				Address addr = info_guessed_addr_map.get(calling_func_info_list.get(idx - 1).get_addr());
				if (addr == null) {
					continue;
				}
				String matched_name = calling_func_info_list.get(idx).get_name();
				if (matched_name == null) {
					continue;
				}
				guessed_names_holder.put(addr.add(diff), matched_name, GuessedConfidence.MEDIUM);
				guessed_info_addr_map.put(addr, calling_func_info_list.get(idx).get_addr());
				info_guessed_addr_map.put(calling_func_info_list.get(idx).get_addr(), addr);
				mapped_arr[idx] = true;
			}
		}
	}

	private void parse_line(String line, List<CallingFuncInfo> holder) {
		String[] line_split = line.split("\\|");
		if (line_split.length < 3 || line_split[1].isEmpty()) {
			return;
		}
		List<String> calling_func_list = new LinkedList<>();
		for (int i = 3; i < line_split.length; i++) {
			calling_func_list.add(line_split[i]);
		}
		holder.add(new CallingFuncInfo(Long.valueOf(line_split[0], 16), line_split[1], line_split[2],
				common_file.get_pre_func_name_list(line_split[1]), common_file.get_post_func_name_list(line_split[1]), calling_func_list));
	}

	private List<CallingFuncInfo> parse_calling_func_file(String file_name) {
		List<CallingFuncInfo> ret = new LinkedList<>();
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
