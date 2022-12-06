package golanganalyzerextension;

import ghidra.program.model.address.Address;

public class FileLine {

	private Address func_addr;
	private int offset;
	private int size;
	private String file_name;
	private long line_num;

	FileLine(Address func_addr, int offset, int size, String file_name, long line_num) {
		this.func_addr=func_addr;
		this.offset=offset;
		this.size=size;
		this.file_name=file_name;
		this.line_num=line_num;
	}

	public Address get_func_addr() {
		return func_addr;
	}

	public Address get_address() {
		return func_addr.add(offset);
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