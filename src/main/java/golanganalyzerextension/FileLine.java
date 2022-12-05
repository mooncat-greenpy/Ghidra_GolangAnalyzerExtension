package golanganalyzerextension;

public class FileLine {

	private String file_name;
	private long line_num;

	FileLine(String file_name, long line_num) {
		this.file_name=file_name;
		this.line_num=line_num;
	}

	public String get_file_name() {
		return file_name;
	}

	public long get_line_num() {
		return line_num;
	}

	@Override
	public String toString() {
		return String.format("%s:%d", file_name, line_num);
	}
}