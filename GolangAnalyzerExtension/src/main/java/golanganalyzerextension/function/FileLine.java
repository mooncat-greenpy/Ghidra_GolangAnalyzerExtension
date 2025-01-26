package golanganalyzerextension.function;

import java.io.Serializable;

import ghidra.program.model.address.Address;

public class FileLine implements Serializable {

	private long func_addr_value;
	private int offset;
	private int size;
	private String file_name;
	private long line_num;

	FileLine(Address func_addr, int offset, int size, String file_name, long line_num) {
		this.func_addr_value=func_addr.getOffset();
		this.offset=offset;
		this.size=size;
		this.file_name=file_name;
		this.line_num=line_num;
	}

	public long get_func_addr() {
		return func_addr_value;
	}

	public int get_offset() {
		return offset;
	}

	public int get_size() {
		return size;
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