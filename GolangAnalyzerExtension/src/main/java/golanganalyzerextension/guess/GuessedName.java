package golanganalyzerextension.guess;

import ghidra.program.model.address.Address;

public class GuessedName {
	private Address addr;
	private String name;
	private GuessedConfidence confidence;

	GuessedName(Address addr, String name, GuessedConfidence confidence) {
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
}