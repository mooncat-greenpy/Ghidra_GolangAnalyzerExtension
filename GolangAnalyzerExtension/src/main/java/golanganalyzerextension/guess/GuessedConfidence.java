package golanganalyzerextension.guess;

public enum GuessedConfidence {
	VERY_LOW,
	LOW,
	MEDIUM,
	HIGH,
	VERY_HIGH;

	public GuessedConfidence prev() {
		switch (this) {
			case VERY_LOW:
				return VERY_LOW;
			case LOW:
				return VERY_LOW;
			case MEDIUM:
				return LOW;
			case HIGH:
				return MEDIUM;
			case VERY_HIGH:
				return HIGH;
			default:
				return this;
		}
	}

	public int priority() {
		switch (this) {
			case VERY_LOW:
				return 0;
			case LOW:
				return 1;
			case MEDIUM:
				return 2;
			case HIGH:
				return 3;
			case VERY_HIGH:
				return 4;
			default:
				return 0;
		}
	}
}
