package golanganalyzerextension.gobinary;

import ghidra.program.model.address.Address;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;

// Parses the WebAssembly module bytes that the Ghidra Wasm loader places at
// ram:CODE_BASE in order to recover the funcID -> Ghidra-address mapping
// the loader assigned. Needed because Go's WASM pclntab uses packed
// pseudo-PCs of the form (funcID << 16), not flat memory addresses.
public class WasmLayout {

	public static final long IMPORT_BASE = 0x7f000000L;
	public static final long CODE_BASE   = 0x80000000L;

	private final GolangBinary go_bin;
	private long[] func_addrs;
	private long[] func_sizes;
	private int num_imports;
	private boolean parsed;
	private boolean ok;

	public WasmLayout(GolangBinary go_bin) {
		this.go_bin = go_bin;
		this.parsed = false;
		this.ok = false;
	}

	public boolean ensure_parsed() {
		if (parsed) {
			return ok;
		}
		parsed = true;
		try {
			parse();
			ok = true;
		} catch (BinaryAccessException e) {
			Logger.append_message(String.format("Failed to parse WASM layout: %s", e.getMessage()));
			ok = false;
		}
		return ok;
	}

	public int get_num_funcs() {
		return func_addrs == null ? 0 : func_addrs.length;
	}

	public int get_num_imports() {
		return num_imports;
	}

	public Address get_func_addr(int func_idx) throws BinaryAccessException {
		if (!ensure_parsed() || func_idx < 0 || func_idx >= func_addrs.length) {
			throw new BinaryAccessException(String.format("WASM funcID out of range: %d", func_idx));
		}
		return go_bin.get_address(func_addrs[func_idx]);
	}

	public long get_func_size(int func_idx) {
		if (!ensure_parsed() || func_idx < 0 || func_idx >= func_sizes.length) {
			return 0;
		}
		return func_sizes[func_idx];
	}

	private void parse() throws BinaryAccessException {
		Address module_base = go_bin.get_address(CODE_BASE);
		long magic = go_bin.get_address_value(module_base, 0, 4);
		if (magic != 0x6d736100L) {
			throw new BinaryAccessException(String.format("Bad WASM magic: %x", magic));
		}

		long cursor = 8;
		int[] code_offsets = null;
		int[] code_sizes = null;
		num_imports = 0;
		boolean code_seen = false;

		while (true) {
			long section_id;
			try {
				section_id = go_bin.get_address_value(module_base, cursor, 1);
			} catch (BinaryAccessException e) {
				break;
			}
			cursor += 1;

			long[] len_pair = read_uleb128(module_base, cursor);
			long section_size = len_pair[0];
			cursor += len_pair[1];
			long section_start = cursor;
			long section_end = section_start + section_size;

			if (section_id == 2) {
				num_imports = parse_imports(module_base, section_start);
			} else if (section_id == 10) {
				long sub_cursor = section_start;
				long[] cnt_pair = read_uleb128(module_base, sub_cursor);
				int code_count = (int) cnt_pair[0];
				sub_cursor += cnt_pair[1];
				code_offsets = new int[code_count];
				code_sizes = new int[code_count];
				for (int i = 0; i < code_count; i++) {
					long[] sz_pair = read_uleb128(module_base, sub_cursor);
					int body_size = (int) sz_pair[0];
					sub_cursor += sz_pair[1];
					code_offsets[i] = (int) sub_cursor;
					code_sizes[i] = body_size;
					sub_cursor += body_size;
				}
				code_seen = true;
			}

			cursor = section_end;
			if (code_seen && num_imports >= 0) {
				if (section_id == 10) {
					break;
				}
			}
		}

		int total = num_imports + (code_offsets == null ? 0 : code_offsets.length);
		func_addrs = new long[total];
		func_sizes = new long[total];
		for (int i = 0; i < num_imports; i++) {
			func_addrs[i] = IMPORT_BASE + 4L * i;
			func_sizes[i] = 4;
		}
		if (code_offsets != null) {
			for (int i = 0; i < code_offsets.length; i++) {
				func_addrs[num_imports + i] = CODE_BASE + code_offsets[i];
				func_sizes[num_imports + i] = code_sizes[i];
			}
		}
	}

	private int parse_imports(Address module_base, long start) throws BinaryAccessException {
		long cursor = start;
		long[] cnt_pair = read_uleb128(module_base, cursor);
		int count = (int) cnt_pair[0];
		cursor += cnt_pair[1];
		int func_imports = 0;
		for (int i = 0; i < count; i++) {
			long[] mod_len = read_uleb128(module_base, cursor);
			cursor += mod_len[1] + mod_len[0];
			long[] nm_len = read_uleb128(module_base, cursor);
			cursor += nm_len[1] + nm_len[0];
			long kind = go_bin.get_address_value(module_base, cursor, 1);
			cursor += 1;
			if (kind == 0) {
				long[] type_pair = read_uleb128(module_base, cursor);
				cursor += type_pair[1];
				func_imports++;
			} else if (kind == 1) {
				cursor += 1;
				long[] el = read_uleb128(module_base, cursor);
				cursor += el[1];
				long limit_flags = go_bin.get_address_value(module_base, cursor, 1);
				cursor += 1;
				long[] init = read_uleb128(module_base, cursor);
				cursor += init[1];
				if ((limit_flags & 1) != 0) {
					long[] max = read_uleb128(module_base, cursor);
					cursor += max[1];
				}
			} else if (kind == 2) {
				long limit_flags = go_bin.get_address_value(module_base, cursor, 1);
				cursor += 1;
				long[] init = read_uleb128(module_base, cursor);
				cursor += init[1];
				if ((limit_flags & 1) != 0) {
					long[] max = read_uleb128(module_base, cursor);
					cursor += max[1];
				}
			} else if (kind == 3) {
				cursor += 1;
				cursor += 1;
			} else {
				throw new BinaryAccessException(String.format("Unknown WASM import kind: %d", kind));
			}
		}
		return func_imports;
	}

	private long[] read_uleb128(Address base, long offset) throws BinaryAccessException {
		long value = 0;
		int shift = 0;
		long consumed = 0;
		while (true) {
			long b = go_bin.get_address_value(base, offset + consumed, 1) & 0xff;
			value |= (b & 0x7f) << shift;
			consumed++;
			if ((b & 0x80) == 0) {
				break;
			}
			shift += 7;
			if (shift > 63) {
				throw new BinaryAccessException("LEB128 too long");
			}
		}
		return new long[] { value, consumed };
	}
}
