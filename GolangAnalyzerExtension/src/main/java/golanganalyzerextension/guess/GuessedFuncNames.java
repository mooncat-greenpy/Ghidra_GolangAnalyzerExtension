package golanganalyzerextension.guess;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;

public class GuessedFuncNames {

	public enum GuessedTrusted {
		VERY_LOW,
		LOW,
		MEDIUM,
		HIGH,
		VERY_HIGH;
	}

	class GuessedName {
		private String name;
		private GuessedTrusted trusted;

		GuessedName(String name, GuessedTrusted trusted) {
			this.name = name;
			this.trusted = trusted;
		}

		public String get_name() {
			return name;
		}

		public GuessedTrusted get_trusted() {
			return trusted;
		}
	}

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

	public GuessedTrusted get_trusted(Address addr) {
		GuessedName gussed = funcs.get(addr);
		if (gussed == null) {
			return null;
		}
		return gussed.get_trusted();
	}

	public void put(Address addr, String name, GuessedTrusted trusted) {
		GuessedTrusted old_trusted = get_trusted(addr);
		if (old_trusted != null && old_trusted.ordinal() > trusted.ordinal()) {
			return;
		}
		funcs.put(addr, new GuessedName(name, trusted));
	}
}
