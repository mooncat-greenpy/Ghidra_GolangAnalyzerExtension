package golanganalyzerextension.guess;

import ghidra.program.model.address.Address;

public class GuessedName {
	private Address addr;
	private String name;
	private GuessedConfidence confidence;

	public GuessedName(Address addr, String name, GuessedConfidence confidence) {
		this.addr = addr;
		this.name = name;
		this.confidence = confidence;
	}

	public Address get_addr() {
		return addr;
	}

	public String get_name() {
		return name;
	}

	public GuessedConfidence get_confidence() {
		return confidence;
	}

	@Override
	public String toString() {
		return String.format(String.format("{addr=%s, name=%s, confidence=%s}", addr, name, confidence));
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (obj == null || this.getClass() != obj.getClass()) {
			return false;
		}

		GuessedName gn_obj = (GuessedName) obj;
		return this.get_addr().equals(gn_obj.get_addr()) &&
				this.get_name().equals(gn_obj.get_name()) &&
				this.get_confidence().equals(gn_obj.get_confidence());
	}
}