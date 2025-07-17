package golanganalyzerextension.guess;

import java.util.Collection;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;

import ghidra.program.model.address.Address;

public class GuessedFuncNames {

	private Map<Address, GuessedName> funcs;

	public GuessedFuncNames() {
		funcs = new HashMap<>();
	}

	public String get_name(Address addr) {
		GuessedName gussed = funcs.get(addr);
		if (gussed == null) {
			return null;
		}
		return gussed.get_name();
	}

	public GuessedConfidence get_confidence(Address addr) {
		GuessedName gussed = funcs.get(addr);
		if (gussed == null) {
			return null;
		}
		return gussed.get_confidence();
	}

	public Set<Address> addrs() {
		return funcs.keySet();
	}

	public Collection<GuessedName> guessed_names() {
		return funcs.values();
	}

	public int size() {
		return funcs.size();
	}

	public void put(Address addr, String name, GuessedConfidence confidence) {
		GuessedConfidence old_confidence = get_confidence(addr);
		if (old_confidence != null && old_confidence.ordinal() > confidence.ordinal()) {
			return;
		}
		funcs.put(addr, new GuessedName(addr, name, confidence));
	}

	public void remove(Address addr) {
		funcs.remove(addr);
	}
}
