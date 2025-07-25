package golanganalyzerextension.guess;

import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import ghidra.app.cmd.function.CreateFunctionCmd;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.MemoryAccessException;
import ghidra.program.model.symbol.FlowType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

import golanganalyzerextension.AnalyzerOption;
import golanganalyzerextension.function.GolangFunctionRecord;
import golanganalyzerextension.log.Logger;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;
import golanganalyzerextension.version.GolangVersion;


public class FuncNameGuesser {
	private Program program;
	private GolangAnalyzerExtensionService service;
	private AnalyzerOption analyzer_option;

	private GolangBsim golang_bsim;
	private CallingFuncNameResource calling_func_name_res;
	private GuessedFuncNames guessed_names_holder;

	public FuncNameGuesser(Program program, GolangAnalyzerExtensionService service, AnalyzerOption analyzer_option) {
		this.program = program;
		this.service = service;
		this.analyzer_option = analyzer_option;
	}

	public GolangVersion get_go_version() {
		if (GolangVersion.is_go_version(analyzer_option.get_go_version())) {
			return new GolangVersion(analyzer_option.get_go_version());
		}
		return golang_bsim.get_go_version();
	}

	public String get_os() {
		return golang_bsim.get_os();
	}

	public String get_arch() {
		return golang_bsim.get_arch();
	}

	public GuessedFuncNames get_funcs() {
		return guessed_names_holder;
	}

	public void guess() {
		guessed_names_holder = new GuessedFuncNames();

		golang_bsim = new GolangBsim(program);
		if (!golang_bsim.guess(guessed_names_holder)) {
			return;
		}

		Address entry_point = get_entry_point();
		guessed_names_holder.put(entry_point, String.format("_rt0_%s_%s", get_arch(), get_os()), GuessedConfidence.VERY_HIGH);

		Logger.append_message(String.format("Guessed information: go_version=%s", get_go_version().get_version_str()));

		calling_func_name_res = new CallingFuncNameResource(get_os(), get_arch(), get_go_version().get_version_str());
		calling_func_name_res.guess_func_name_by_file_line(program, program.getListing().getFunctions(true), guessed_names_holder);
		guess_calling_func();
	}

	private void create_function(String name, Address addr) {
		CreateFunctionCmd cmd=new CreateFunctionCmd(name, addr, null, SourceType.ANALYSIS);
		cmd.applyTo(program, TaskMonitor.DUMMY);
	}

	private List<Address> get_calling_func_list(Address addr) {
		Instruction inst = program.getListing().getInstructionAt(addr);
		List<Address> calling_func_list = new LinkedList<>();
		while (inst != null) {
			for (Reference ref : inst.getReferencesFrom()) {
				if (ref.getReferenceType().isCall()) {
					calling_func_list.add(ref.getToAddress());
				} else if (ref.getReferenceType().isJump()) {
					if (is_go_func_entry_point(ref.getToAddress())) {
						calling_func_list.add(ref.getToAddress());
					}
				}
			}

			inst = program.getListing().getInstructionAt(inst.getAddress().add(inst.getParsedLength()));
		}
		return calling_func_list;
	}

	private void analyze_calling_func(GuessedName src_guessed_name, Map<Address, List<GuessedName>> func_name_map) {
		List<Address> calling_func_list = get_calling_func_list(src_guessed_name.get_addr());

		CallingFuncInfo calling_func_info = calling_func_name_res.get_calling_func_info_list(src_guessed_name, calling_func_list.size());
		if (calling_func_info == null) {
			return;
		}
		List<String> pre_calling_name_list = calling_func_info.get_pre();
		List<String> post_calling_name_list = calling_func_info.get_post();
		List<String> calling_name_list = calling_func_info.get_calling();

		int half = calling_name_list.size() / 2;
		for (int i = 0; i < calling_func_list.size() && i < calling_name_list.size(); i++) {
			String calling_name;
			Address calling_addr;
			if (i <= half) {
				calling_name = calling_name_list.get(i);
				calling_addr = calling_func_list.get(i);
			} else {
				calling_name = calling_name_list.get(calling_name_list.size() - (i - half));
				calling_addr = calling_func_list.get(calling_func_list.size() - (i - half));
			}

			GuessedConfidence confidence = src_guessed_name.get_confidence();
			if (confidence.equals(GuessedConfidence.VERY_HIGH)) {
				confidence = confidence.prev();
			}
			GuessedName guessed_name = new GuessedName(calling_addr, calling_name, confidence);
			if (!func_name_map.containsKey(calling_addr)) {
				func_name_map.put(calling_addr, new LinkedList<>() {{add(guessed_name);}});
			} else {
				func_name_map.get(calling_addr).add(guessed_name);
			}
			if (func_name_map.get(calling_addr).stream().filter(v -> v.get_name().equals(calling_name) && v.get_confidence().equals(guessed_name.get_confidence())).count() >= 2) {
				continue;
			}

			analyze_calling_func(guessed_name, func_name_map);
		}

		for (int i = 0; i < calling_func_list.size() && i < pre_calling_name_list.size(); i++) {
			Address calling_addr = calling_func_list.get(i);
			String calling_name = pre_calling_name_list.get(i);
			GuessedName guessed_name = new GuessedName(calling_addr, calling_name, src_guessed_name.get_confidence());
			if (!func_name_map.containsKey(calling_addr)) {
				func_name_map.put(calling_addr, new LinkedList<>() {{add(guessed_name);}});
			} else {
				func_name_map.get(calling_addr).add(guessed_name);
			}
			if (func_name_map.get(calling_addr).stream().filter(v -> v.get_name().equals(calling_name) && v.get_confidence().equals(guessed_name.get_confidence())).count() >= 2) {
				continue;
			}

			analyze_calling_func(guessed_name, func_name_map);
		}
		for (int i = 0; i < calling_func_list.size() && i < post_calling_name_list.size(); i++) {
			Address calling_addr = calling_func_list.get(calling_func_list.size() - 1 - i);
			String calling_name = post_calling_name_list.get(post_calling_name_list.size() - 1 - i);
			GuessedName guessed_name = new GuessedName(calling_addr, calling_name, src_guessed_name.get_confidence());
			if (!func_name_map.containsKey(calling_addr)) {
				func_name_map.put(calling_addr, new LinkedList<>() {{add(guessed_name);}});
			} else {
				func_name_map.get(calling_addr).add(guessed_name);
			}
			if (func_name_map.get(calling_addr).stream().filter(v -> v.get_name().equals(calling_name) && v.get_confidence().equals(guessed_name.get_confidence())).count() >= 2) {
				continue;
			}

			analyze_calling_func(guessed_name, func_name_map);
		}
	}

	private void apply_calling_func_analyzed(Map<Address, List<GuessedName>> func_name_map) {
		for (Map.Entry<Address, List<GuessedName>> entry : func_name_map.entrySet()) {
			Map<String, List<GuessedName>> freq_map = new HashMap<>();
			for (GuessedName name : entry.getValue()) {
				List<GuessedName> tmp = freq_map.getOrDefault(name.get_name(), new LinkedList<>());
				tmp.add(name);
				freq_map.put(name.get_name(), tmp);
			}
			int count = 0;
			String freq_name = null;
			GuessedConfidence confidence = GuessedConfidence.VERY_LOW;
			for (Map.Entry<String, List<GuessedName>> freq_entry : freq_map.entrySet()) {
				GuessedConfidence tmp_confidence = GuessedConfidence.VERY_LOW;
				for (GuessedName guessed_name : freq_map.get(freq_entry.getKey())) {
					if (guessed_name.get_confidence().priority() > tmp_confidence.priority()) {
						tmp_confidence = guessed_name.get_confidence();
					}
				}
				if (tmp_confidence.priority() > confidence.priority() ||
						(tmp_confidence.priority() == confidence.priority() && freq_entry.getValue().size() >= count)) {
					freq_name = freq_entry.getKey();
					confidence = tmp_confidence;
					count = freq_entry.getValue().size();
				}
			}
			if (freq_name == null) {
				continue;
			}

			guessed_names_holder.put(entry.getKey(), freq_name, confidence);
		}
	}

	private void guess_calling_func() {
		Map<Address, List<GuessedName>> func_name_map = new HashMap<>();
		for (Address addr : new HashSet<>(guessed_names_holder.addrs())) {
			analyze_calling_func(new GuessedName(addr, guessed_names_holder.get_name(addr), guessed_names_holder.get_confidence(addr)), func_name_map);
		}
		apply_calling_func_analyzed(func_name_map);

		guess_runtime_main();

		FunctionIterator itr = program.getListing().getFunctions(true);
		calling_func_name_res.get_func_name_by_placement(itr, guessed_names_holder);

		for (int i = 0; i < 5; i++) {
			calling_func_name_res.collect_func_name_by_placement(guessed_names_holder);
		}

		guess_main();
	}

	private void guess_runtime_main() {
		GuessedName runtime_rt0_go = null;
		GuessedName runtime_newproc = null;
		for (GuessedName guessed_name : guessed_names_holder.guessed_names()) {
			if (guessed_name.get_name().equals("runtime.rt0_go")) {
				runtime_rt0_go = guessed_name;
			} else if (guessed_name.get_name().equals("runtime.newproc")) {
				runtime_newproc = guessed_name;
			}
		}
		if (runtime_rt0_go == null || runtime_newproc == null) {
			Logger.append_message(String.format("Failed to guess runtime.main: rt0_go=%s newproc=%s", runtime_rt0_go, runtime_newproc));
			return;
		}

		Instruction newproc_inst = null;
		for (Instruction inst = program.getListing().getInstructionAt(runtime_rt0_go.get_addr());
				inst != null && newproc_inst == null;
				inst = program.getListing().getInstructionAt(inst.getAddress().add(inst.getParsedLength()))) {
			if (!inst.getFlowType().isCall()) {
				continue;
			}
			Address[] call_addrs = inst.getFlows();
			for (Address addr : call_addrs) {
				if (addr.equals(runtime_newproc.get_addr())) {
					newproc_inst = inst;
					break;
				}
			}
		}
		if (newproc_inst == null) {
			Logger.append_message(String.format("Failed to get newproc in rt0_go: rt0_go=%s newproc=%s", runtime_rt0_go, runtime_newproc));
			return;
		}
		for (Instruction inst = newproc_inst.getPrevious(); inst != null; inst = inst.getPrevious()) {
			if (inst.getFlowType().isCall()) {
				break;
			}
			for (Reference ref : inst.getReferencesFrom()) {
				if (is_valid_address(ref.getToAddress())) {
					Data data = program.getListing().getDataAt(ref.getToAddress());
					if (data != null && data.isPointer()) {
						Address runtime_main_addr = (Address) data.getValue();
						if (is_go_func_entry_point(runtime_main_addr)) {
							guessed_names_holder.put(runtime_main_addr, "runtime.main", runtime_rt0_go.get_confidence());
							Map<Address, List<GuessedName>> func_name_map = new HashMap<>();
							analyze_calling_func(new GuessedName(runtime_main_addr, guessed_names_holder.get_name(runtime_main_addr), guessed_names_holder.get_confidence(runtime_main_addr)), func_name_map);
							apply_calling_func_analyzed(func_name_map);
							return;
						}
					}
				}
			}
		}
	}

	private void guess_main() {
		GuessedName runtime_main = null;
		GuessedName runtime_unlockOSThread = null;
		for (GuessedName guessed_name : guessed_names_holder.guessed_names()) {
			if (guessed_name.get_name().equals("runtime.main")) {
				runtime_main = guessed_name;
			} else if (guessed_name.get_name().equals("runtime.unlockOSThread")) {
				runtime_unlockOSThread = guessed_name;
			}
		}
		if (runtime_main == null || runtime_unlockOSThread == null) {
			return;
		}

		boolean after_unlockOSThread = false;
		for (Instruction inst = program.getListing().getInstructionAt(runtime_main.get_addr());
				inst != null;
				inst = program.getListing().getInstructionAt(inst.getAddress().add(inst.getParsedLength()))) {
			if (!inst.getFlowType().isCall()) {
				continue;
			}
			Address[] call_addrs = inst.getFlows();
			if (after_unlockOSThread == true) {
				if (inst.getFlowType() == FlowType.COMPUTED_CALL && call_addrs.length == 1) {
					guessed_names_holder.put(call_addrs[0], "main.main", runtime_main.get_confidence());
				}
				return;
			}
			for (Address addr : call_addrs) {
				if (addr.equals(runtime_unlockOSThread.get_addr())) {
					after_unlockOSThread = true;
					break;
				}
			}
		}
	}

	private boolean is_go_func_entry_point(Address addr) {
		Function func = get_function(addr);
		if (func != null && func.getEntryPoint().equals(addr)) {
			return true;
		}
		Instruction inst = program.getListing().getInstructionAt(addr);
		Instruction prev_inst = inst.getPrevious();
		if (prev_inst == null) {
			return true;
		}
		Address prev_addr = prev_inst.getAddress();
		if (addr.getOffset() > prev_addr.getOffset() + prev_inst.getParsedLength() + 1) {
			return true;
		}
		return false;
	}

	private Address get_entry_point() {
		FunctionIterator itr = program.getListing().getFunctions(true);
		while (itr.hasNext()) {
			Function func = itr.next();
			Address addr = func.getEntryPoint();
			Instruction inst = program.getListing().getInstructionAt(addr);
			if (inst == null) {
				continue;
			}
			for (Reference ref : inst.getReferenceIteratorTo()) {
				if (ref.getFromAddress().toString().equals("Entry Point")) {
					return addr;
				}
			}
		}
		return null;
	}

	private Function get_function(Address addr) {
		return program.getFunctionManager().getFunctionAt(addr);
	}

	private boolean is_valid_address(Address addr) {
		if(addr==null) {
			return false;
		}
		boolean ret=false;
		try {
			program.getMemory().getByte(addr);
			ret=true;
		} catch (MemoryAccessException e) {
			ret=false;
		}
		return ret;
	}

	// TODO: Fix
	// Parser -> Modifier
	// Guesser -> Modifier
	public void rename_func_for_guess(GuessedFuncNames func_name_map) {
		for (GuessedName entry : func_name_map.guessed_names()) {
			if (entry.get_confidence().ordinal() < analyzer_option.get_guess_confidence_func().ordinal()) {
				continue;
			}
			String func_name = entry.get_name() + "_GAEguess";
			Function func = get_function(entry.get_addr());
			if (func == null) {
				create_function(func_name, entry.get_addr());
				continue;
			}
			if (!func.getName().contains("FUN_") && !func.getName().contains("entry")) {
				continue;
			}
			try {
				func.setName(func_name, SourceType.USER_DEFINED);
				service.add_function(new GolangFunctionRecord(func.getEntryPoint(), func_name, 0, 0, new HashMap<>(), new HashMap<>(), new Parameter[]{}));
			}catch(Exception e) {
				Logger.append_message(String.format("Failed to set function name: addr=%s, message=%s", entry.get_addr(), e.getMessage()));
			}
		}
	}
}
