package golanganalyzerextension.gobinary;

import ghidra.program.model.address.Address;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;

public class PcHeader {

	private static final byte[] GO_12_MAGIC_LITTLE={(byte)0xfb,(byte)0xff,(byte)0xff,(byte)0xff};
	private static final byte[] GO_12_MAGIC_BIG={(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xfb};
	private static final byte[] GO_116_MAGIC_LITTLE={(byte)0xfa,(byte)0xff,(byte)0xff,(byte)0xff};
	private static final byte[] GO_116_MAGIC_BIG={(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xfa};
	private static final byte[] GO_118_MAGIC_LITTLE={(byte)0xf0,(byte)0xff,(byte)0xff,(byte)0xff};
	private static final byte[] GO_118_MAGIC_BIG={(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xf0};
	private static final byte[] GO_120_MAGIC_LITTLE={(byte)0xf1,(byte)0xff,(byte)0xff,(byte)0xff};
	private static final byte[] GO_120_MAGIC_BIG={(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xf1};
	private static final byte[] MAGIC_MASK={(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};

	private GolangBinary go_bin;

	private Address addr;
	private int quantum;
	private int pointer_size;
	private GO_VERSION go_version;
	private boolean little_endian;

	public enum GO_VERSION {
		GO_12,
		GO_116,
		GO_118,
		GO_120;

		public static GO_VERSION from_integer(int num) throws IllegalArgumentException {
			switch(num) {
			case 12:
				return GO_12;
			case 116:
				return GO_116;
			case 118:
				return GO_118;
			case 120:
				return GO_120;
			}

			throw new IllegalArgumentException(String.format("Invalid PcHeader.GO_VERSION: num=%d", num));
		}

		public static int to_integer(GO_VERSION go_version) {
			switch(go_version) {
			case GO_12:
				return 12;
			case GO_116:
				return 116;
			case GO_118:
				return 118;
			default:
				return 120;
			}
		}
	}

	public PcHeader(GolangBinary go_bin) throws InvalidBinaryStructureException {
		this.go_bin=go_bin;

		this.addr=search_by_magic();
	}

	public PcHeader(GolangBinary go_bin, Address target_addr, GO_VERSION go_version, boolean little_endian) throws InvalidBinaryStructureException {
		this.go_bin=go_bin;

		this.addr=search_by_magic(target_addr, go_version, little_endian);
	}

	public Address get_addr() {
		return addr;
	}

	public int get_quantum() {
		return quantum;
	}

	public int get_pointer_size() {
		return pointer_size;
	}

	public GO_VERSION get_go_version() {
		return go_version;
	}

	public boolean is_little_endian() {
		return little_endian;
	}

	private Address search_by_magic() {
		Address result_addr=null;
		if(result_addr==null) {
			result_addr=search_by_magic(null, GO_VERSION.GO_12, true);
		}
		if(result_addr==null) {
			result_addr=search_by_magic(null, GO_VERSION.GO_12, false);
		}
		if(result_addr==null) {
			result_addr=search_by_magic(null, GO_VERSION.GO_116, true);
		}
		if(result_addr==null) {
			result_addr=search_by_magic(null, GO_VERSION.GO_116, false);
		}
		if(result_addr==null) {
			result_addr=search_by_magic(null, GO_VERSION.GO_118, true);
		}
		if(result_addr==null) {
			result_addr=search_by_magic(null, GO_VERSION.GO_118, false);
		}
		if(result_addr==null) {
			result_addr=search_by_magic(null, GO_VERSION.GO_120, true);
		}
		if(result_addr==null) {
			result_addr=search_by_magic(null, GO_VERSION.GO_120, false);
		}

		if(result_addr==null) {
			throw new InvalidBinaryStructureException("Not found pcHeader");
		}
		return result_addr;
	}

	private Address search_by_magic(Address target_addr, GO_VERSION target_go_version, boolean target_little_endian) {
		// debug/gosym/pclntab.go
		boolean is_go118=target_go_version.equals(GO_VERSION.GO_118) | target_go_version.equals(GO_VERSION.GO_120);
		boolean is_go116=target_go_version.equals(GO_VERSION.GO_116);

		byte[] magic;
		if(target_go_version.equals(GO_VERSION.GO_12)) {
			if(target_little_endian) {
				magic=GO_12_MAGIC_LITTLE;
			} else {
				magic=GO_12_MAGIC_BIG;
			}
		} else if(target_go_version.equals(GO_VERSION.GO_116)) {
			if(target_little_endian) {
				magic=GO_116_MAGIC_LITTLE;
			} else {
				magic=GO_116_MAGIC_BIG;
			}
		} else if(target_go_version.equals(GO_VERSION.GO_118)) {
			if(target_little_endian) {
				magic=GO_118_MAGIC_LITTLE;
			} else {
				magic=GO_118_MAGIC_BIG;
			}
		} else {
			if(target_little_endian) {
				magic=GO_120_MAGIC_LITTLE;
			} else {
				magic=GO_120_MAGIC_BIG;
			}
		}

		Address tmp_addr=target_addr;
		while(true) {
			tmp_addr=go_bin.find_memory(tmp_addr, magic, MAGIC_MASK).orElse(null);
			if(tmp_addr==null) {
				break;
			}

			try {
				// magic
				// two zero bytes
				quantum=(int)go_bin.get_address_value(tmp_addr, 6, 1);      // arch(x86=1, ?=2, arm=4)
				pointer_size=(int)go_bin.get_address_value(tmp_addr, 7, 1); // pointer size

				Address func_list_base;
				if(is_go118) {
					func_list_base=go_bin.get_address(tmp_addr, go_bin.get_address_value(tmp_addr, 8+pointer_size*7, pointer_size));
				}else if(is_go116) {
					func_list_base=go_bin.get_address(tmp_addr, go_bin.get_address_value(tmp_addr, 8+pointer_size*6, pointer_size));
				}else {
					func_list_base=go_bin.get_address(tmp_addr, 8+pointer_size);
				}
				long func_addr_value=go_bin.get_address_value(func_list_base, 0, is_go118?4:pointer_size);
				long func_info_offset=go_bin.get_address_value(func_list_base, is_go118?4:pointer_size, is_go118?4:pointer_size);
				long func_entry_value;
				if(is_go118) {
					func_entry_value=go_bin.get_address_value(func_list_base, func_info_offset, 4);
				} else if(is_go116) {
					func_entry_value=go_bin.get_address_value(func_list_base, func_info_offset, pointer_size);
				} else {
					func_entry_value=go_bin.get_address_value(tmp_addr, func_info_offset, pointer_size);
				}

				if((quantum==1 || quantum==2 || quantum==4) && (pointer_size==4 || pointer_size==8) &&
						func_addr_value==func_entry_value && (is_go118 || func_addr_value!=0)) {
					go_version=target_go_version;
					little_endian=target_little_endian;
					return tmp_addr;
				}
			} catch (BinaryAccessException e) {
			}
			try {
				tmp_addr=go_bin.get_address(tmp_addr, 4);
			} catch (BinaryAccessException e) {
				break;
			}
		}

		return null;
	}
}
