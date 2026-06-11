package golanganalyzerextension.gobinary;

import ghidra.program.model.address.Address;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;

public class WasmLayout {

	public static final long SECTION_ID_IMPORT = 2;
	public static final long SECTION_ID_CODE = 10;

	public static final long EXTERN_TYPE_TYPEIDX = 0;
	public static final long EXTERN_TYPE_TABLETYPE = 1;
	public static final long EXTERN_TYPE_MEMTYPE = 2;
	public static final long EXTERN_TYPE_GLOBALTYPE = 3;
	public static final long EXTERN_TYPE_TAGTYPE = 4;

	private static final byte[] WASM_MODULE_HEADER = new byte[] {
		(byte) 0x00, (byte) 0x61, (byte) 0x73, (byte) 0x6d,
		(byte) 0x01, (byte) 0x00, (byte) 0x00, (byte) 0x00,
	};
	private static final byte[] WASM_MODULE_HEADER_MASK = new byte[] {
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
		(byte) 0xff, (byte) 0xff, (byte) 0xff, (byte) 0xff,
	};

	private final GolangBinary go_bin;
	private CodeSection code_section;
	private int num_imports;
	private boolean ok;

	private static class CodeSection {
		private final CodeFunction[] functions;

		CodeSection(CodeFunction[] functions) {
			this.functions = functions;
		}

		CodeFunction get_func(int idx) {
			if (idx < 0 || idx >= functions.length) {
				return null;
			}
			return functions[idx];
		}
	}

	private static class CodeFunction {
		private final long addr;
		private final long size;

		CodeFunction(long addr, long size) {
			this.addr = addr;
			this.size = size;
		}
	}

	public WasmLayout(GolangBinary go_bin) {
		this.go_bin = go_bin;
		this.ok = false;
		try {
			parse();
			ok = true;
		} catch (BinaryAccessException e) {
			ok = false;
		}
	}

	public boolean is_parse_successful() {
		return ok;
	}

	public int get_num_imports() {
		return num_imports;
	}

	public Address get_func_addr(int func_idx) throws BinaryAccessException {
		CodeFunction func = get_code_func(func_idx);
		if (func == null) {
			throw new BinaryAccessException(String.format("WASM funcID out of range: %d", func_idx));
		}
		return go_bin.get_address(func.addr);
	}

	public long get_func_size(int func_idx) {
		CodeFunction func = get_code_func(func_idx);
		return func == null ? 0 : func.size;
	}

	private CodeFunction get_code_func(int func_idx) {
		if (code_section == null) {
			return null;
		}
		return code_section.get_func(func_idx - num_imports);
	}

	// https://webassembly.github.io/spec/core/binary/modules.html
	private void parse() throws BinaryAccessException {
		Address module_base = find_module_base();

		long cursor = 8;
		num_imports = 0;

		while (code_section == null || num_imports == 0) {
			long section_id = go_bin.get_address_value(module_base, cursor, 1);
			cursor += 1;

			long[] len_pair = read_uleb128(module_base, cursor);
			long section_size = len_pair[0];
			cursor += len_pair[1];
			long section_start = cursor;
			long section_end = section_start + section_size;

			if (section_id == SECTION_ID_IMPORT) {
				num_imports = parse_imports(module_base, section_start);
			} else if (section_id == SECTION_ID_CODE) {
				code_section = parse_code(module_base, section_start);
			}

			cursor = section_end;
		}
	}

	private Address find_module_base() throws BinaryAccessException {
		return go_bin.find_memory(null, WASM_MODULE_HEADER, WASM_MODULE_HEADER_MASK).orElseThrow(() ->
			new BinaryAccessException("WASM module header not found")
		);
	}

	private CodeSection parse_code(Address module_base, long start) throws BinaryAccessException {
		long module_base_value = module_base.getOffset();
		long cursor = start;
		long[] cnt_pair = read_uleb128(module_base, cursor);
		int code_count = (int) cnt_pair[0];
		cursor += cnt_pair[1];
		CodeFunction[] functions = new CodeFunction[code_count];
		for (int i = 0; i < code_count; i++) {
			long[] sz_pair = read_uleb128(module_base, cursor);
			int body_size = (int) sz_pair[0];
			cursor += sz_pair[1];
			functions[i] = new CodeFunction(module_base_value + cursor, body_size);
			cursor += body_size;
		}
		return new CodeSection(functions);
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
			// https://webassembly.github.io/spec/core/binary/types.html#binary-externtype
			if (kind == EXTERN_TYPE_TYPEIDX) {
				long[] type_pair = read_uleb128(module_base, cursor);
				cursor += type_pair[1];
				func_imports++;
			} else if (kind == EXTERN_TYPE_TABLETYPE) {
				cursor += 1;
				long[] el = read_uleb128(module_base, cursor);
				cursor += el[1];
				long limit_flags = go_bin.get_address_value(module_base, cursor, 1);
				cursor += 1;
				long[] init = read_uleb128(module_base, cursor);
				cursor += init[1];
				// https://webassembly.github.io/spec/core/binary/types.html#limits
				if ((limit_flags & 1) != 0) {
					long[] max = read_uleb128(module_base, cursor);
					cursor += max[1];
				}
			} else if (kind == EXTERN_TYPE_MEMTYPE) {
				long limit_flags = go_bin.get_address_value(module_base, cursor, 1);
				cursor += 1;
				long[] init = read_uleb128(module_base, cursor);
				cursor += init[1];
				// https://webassembly.github.io/spec/core/binary/types.html#limits
				if ((limit_flags & 1) != 0) {
					long[] max = read_uleb128(module_base, cursor);
					cursor += max[1];
				}
			} else if (kind == EXTERN_TYPE_GLOBALTYPE) {
				// https://webassembly.github.io/spec/core/binary/types.html#global-types
				// No support: valtype -> reftype
				cursor += 1;
				cursor += 1;
			} else if (kind == EXTERN_TYPE_TAGTYPE) {
				cursor += 1;
				long[] x = read_uleb128(module_base, cursor);
				cursor += x[1];
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
