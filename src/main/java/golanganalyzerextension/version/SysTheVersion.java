package golanganalyzerextension.version;

import java.util.Optional;

import ghidra.program.model.address.Address;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;

class SysTheVersion {
	private GolangBinary go_bin;

	private Optional<String> go_version_opt;

	SysTheVersion(GolangBinary go_bin) {
		this.go_bin=go_bin;

		go_version_opt=find_sys_the_version();
	}

	Optional<String> get_go_version() {
		return go_version_opt;
	}

	Optional<String> find_sys_the_version() {
		// runtime/proc.go runtime.proc1.go
		// var buildVersion = sys.TheVersion
		Address sys_the_version_addr=null;
		// "go1."
		byte[] version_head=new byte[] {(byte)0x67, (byte)0x6f, (byte)0x31, (byte)0x2e};
		byte[] version_head_mask=new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff};
		while(true) {
			if(sys_the_version_addr!=null) {
				try {
					sys_the_version_addr=go_bin.get_address(sys_the_version_addr, 4);
				} catch (BinaryAccessException e) {
					break;
				}
			}
			sys_the_version_addr=go_bin.find_memory(sys_the_version_addr, version_head, version_head_mask).orElse(null);
			if(sys_the_version_addr==null) {
				break;
			}

			String str;
			try {
				str = go_bin.read_string(sys_the_version_addr, 15);
			} catch (BinaryAccessException e) {
				continue;
			}

			Optional<String> sys_the_version_opt=GolangVersionExtractor.extract_go_version(str);
			if(sys_the_version_opt.isEmpty()) {
				continue;
			}

			long addr_value=sys_the_version_addr.getOffset();
			byte[] addr_bytes=new byte[go_bin.get_pointer_size()];
			byte[] addr_mask=new byte[go_bin.get_pointer_size()];
			for(int i=0; i<go_bin.get_pointer_size(); i++) {
				addr_bytes[i]=(byte)(addr_value&0xff);
				addr_value>>=8;
				addr_mask[i]=(byte)0xff;
			}
			Address string_struct_addr=null;
			while(true) {
				string_struct_addr=go_bin.find_memory(string_struct_addr, addr_bytes, addr_mask).orElse(null);
				if(string_struct_addr==null) {
					break;
				}
				if(check_string_struct(string_struct_addr, sys_the_version_opt.get())) {
					return sys_the_version_opt;
				}
				try {
					string_struct_addr=go_bin.get_address(string_struct_addr, 4);
				} catch (BinaryAccessException e) {
					break;
				}
			}
		}
		return Optional.empty();
	}

	private boolean check_string_struct(Address string_struct_addr, String sys_the_version) {
		Address size_addr;
		long size;
		try {
			size_addr=go_bin.get_address(string_struct_addr, go_bin.get_pointer_size());
			size=go_bin.get_address_value(size_addr, go_bin.get_pointer_size());
		} catch (BinaryAccessException e) {
			return false;
		}
		if(size!=sys_the_version.length()) {
			return false;
		}

		// runtime/proc.go
		boolean badmorestackg0Msg=false;
		boolean badmorestackgsignalMsg=false;
		for(int i=-4; i<4; i++) {
			Address around_str_addr;
			String around_str;
			try {
				around_str_addr=go_bin.get_address(string_struct_addr, go_bin.get_pointer_size()*2*i);
				around_str=go_bin.read_string_struct(around_str_addr, go_bin.get_pointer_size());
			} catch (BinaryAccessException | InvalidBinaryStructureException e) {
				continue;
			}
			if(around_str.contains("fatal: morestack on g0")) {
				badmorestackg0Msg=true;
			}
			if(around_str.contains("fatal: morestack on gsignal")) {
				badmorestackgsignalMsg=true;
			}
		}
		GolangVersion go_version=new GolangVersion(sys_the_version);
		if(go_version.ge("go1.8beta1") && (!badmorestackg0Msg || !badmorestackgsignalMsg)) {
			return false;
		}

		return true;
	}
}
