package golanganalyzerextension.gobinary;

import ghidra.program.model.address.Address;

import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.version.GolangVersion;

public class FuncInfo {
	public class FuncInfoTab {
		private Address func_addr;
		private Address info_addr;
		private Address next_func_addr;

		FuncInfoTab(Address func_addr, Address info_addr, Address next_func_addr) {
			this.func_addr = func_addr;
			this.info_addr = info_addr;
			this.next_func_addr = next_func_addr;
		}

		public Address get_func_addr() {
			return func_addr;
		}

		public Address get_info_addr() {
			return info_addr;
		}

		public Address get_next_func_addr() {
			return next_func_addr;
		}
	}

	private boolean force;
	private FuncInfoTab info_tab;
	private Address func_addr;
	private int name_offset;
	private int arg_size;
	private int pcsp_offset;
	private int pcfile_offset;
	private int pcln_offset;
	private int cu_offset;

	public static FuncInfo create_by_funcinfotab(GolangBinary go_bin, Address func_list_base, Address tab_addr) {
		try {
			return new FuncInfo(go_bin, func_list_base, tab_addr, false);
		} catch(InvalidBinaryStructureException e) {
		}
		return null;
	}

	public FuncInfo(GolangBinary go_bin, Address func_list_base, Address addr, boolean force) throws InvalidBinaryStructureException {
		this.force = force;
		info_tab = parse_func_info_tab(go_bin, func_list_base, addr);
		parse_func_info(go_bin, func_list_base, info_tab);
		return;
	}

	private FuncInfoTab parse_func_info_tab(GolangBinary go_bin, Address func_list_base, Address tab_addr) throws InvalidBinaryStructureException {
		boolean is_go116=false;
		boolean is_go118=false;
		if(go_bin.ge_go_version(GolangVersion.GO_1_16_LOWEST)) {
			is_go116=true;
		}
		if(go_bin.ge_go_version(GolangVersion.GO_1_18_LOWEST)) {
			is_go118=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address pcheader_base=go_bin.get_pcheader_base();

		long func_addr_value;
		Address func_addr;
		long info_offset;
		Address info_addr;
		long func_end_value;
		Address func_end_addr;
		try {
			int functab_field_size=is_go118?4:pointer_size;
			func_addr_value=go_bin.get_address_value(tab_addr, functab_field_size);
			if(is_go118) {
				func_addr_value+=go_bin.get_address_value(pcheader_base, 8+pointer_size*2, pointer_size);
			}
			func_addr = go_bin.get_address(func_addr_value);

			info_offset=go_bin.get_address_value(tab_addr, functab_field_size, functab_field_size);
			if(is_go116) {
				info_addr=go_bin.get_address(func_list_base, info_offset);
			}else {
				info_addr=go_bin.get_address(pcheader_base, info_offset);
			}

			func_end_value=go_bin.get_address_value(tab_addr, functab_field_size*2, functab_field_size);
			if(is_go118) {
				func_end_value+=go_bin.get_address_value(pcheader_base, 8+pointer_size*2, pointer_size);
			}
			func_end_addr=go_bin.get_address(func_end_value);
		} catch (BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Invalid FuncInfo tab: message=%s", e.getMessage()));
		}
		if(func_addr_value==0 || info_offset==0) {
			throw new InvalidBinaryStructureException("Invalid FuncInfo tab entry");
		}

		return new FuncInfoTab(func_addr, info_addr, func_end_addr);
	}

	public FuncInfoTab get_info_tab() {
		return info_tab;
	}
	public Address get_func_addr() {
		return func_addr;
	}
	public int get_name_offset() {
		return name_offset;
	}
	public int get_arg_size() {
		return arg_size;
	}
	public int get_pcsp_offset() {
		return pcsp_offset;
	}
	public int get_pcfile_offset() {
		return pcfile_offset;
	}
	public int get_pcln_offset() {
		return pcln_offset;
	}
	public int get_cu_offset() {
		return cu_offset;
	}

	public long get_func_size() {
		return get_info_tab().get_next_func_addr().getOffset()-get_info_tab().get_func_addr().getOffset();
	}

	@Override
	public String toString() {
		return String.format("{addr=%s}", get_info_tab().get_info_addr());
	}

	private void parse_func_info(GolangBinary go_bin, Address func_list_base, FuncInfoTab info_tab) throws InvalidBinaryStructureException {
		boolean is_go118=false;
		if(go_bin.ge_go_version(GolangVersion.GO_1_18_LOWEST)) {
			is_go118=true;
		}

		int pointer_size=go_bin.get_pointer_size();
		Address pcheader_base=go_bin.get_pcheader_base();

		long func_entry_value;
		try {
			int functab_field_size=is_go118?4:pointer_size;

			func_entry_value=go_bin.get_address_value(info_tab.get_info_addr(), functab_field_size);
			if(is_go118) {
				long text=go_bin.get_address_value(pcheader_base, 8+pointer_size*2, pointer_size);
				func_entry_value+=text;
			}
		} catch (BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Invalid FuncInfo.func_addr: message=%s", e.getMessage()));
		}
		if (func_entry_value==0) {
			throw new InvalidBinaryStructureException("Invalid FuncInfo.func_addr");
		}
		if (info_tab.get_func_addr().getOffset()!=func_entry_value && !force) {
			throw new InvalidBinaryStructureException(String.format("FuncInfo.func_addr mismatch: %x != %x", info_tab.get_func_addr().getOffset(), func_entry_value));
		}

		try {
			func_addr=go_bin.get_address(func_entry_value);
			name_offset=(int)go_bin.get_address_value(info_tab.get_info_addr(), is_go118?4:pointer_size, 4);
			arg_size=(int)go_bin.get_address_value(info_tab.get_info_addr(), (is_go118?4:pointer_size)+4, 4);
			pcsp_offset=(int)go_bin.get_address_value(info_tab.get_info_addr(), (is_go118?4:pointer_size)+3*4, 4);
			pcfile_offset=(int)go_bin.get_address_value(info_tab.get_info_addr(), (is_go118?4:pointer_size)+4*4, 4);
			pcln_offset=(int)go_bin.get_address_value(info_tab.get_info_addr(), (is_go118?4:pointer_size)+5*4, 4);
			cu_offset=(int)go_bin.get_address_value(info_tab.get_info_addr(), (is_go118?4:pointer_size)+4*7, 4);
		} catch (BinaryAccessException e) {
			throw new InvalidBinaryStructureException(String.format("Invalid FuncInfo: message=%s", e.getMessage()));
		}
	}
}
