package golanganalyzerextension;

public class StructField {
	private String name;
	private long type_key;
	private int offset;

	StructField(GolangBinary go_bin, String name, long type_key, int offset){
		this.name=name;
		this.type_key=type_key;
		if(go_bin.ge_go_version("go1.19beta1") || go_bin.lt_go_version("go1.9beta1")) {
			this.offset=offset;
		} else {
			this.offset=offset>>1;
		}
	}

	public String get_name() {
		return name;
	}

	public long get_type_key() {
		return type_key;
	}

	public int get_offset() {
		return offset;
	}
}
