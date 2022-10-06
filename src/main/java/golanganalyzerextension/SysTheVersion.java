package golanganalyzerextension;

import java.util.Optional;

import ghidra.program.model.address.Address;
import golanganalyzerextension.version.GolangVersion;
import golanganalyzerextension.version.GolangVersionExtractor;

public class SysTheVersion {
	private GolangBinary go_bin;

	private Optional<String> go_version_opt;

	public SysTheVersion(GolangBinary go_bin) {
		this.go_bin=go_bin;

		go_version_opt=find_sys_the_version();
	}

	public Optional<String> get_go_version() {
		return go_version_opt;
	}

	public Optional<String> find_sys_the_version() {
		// runtime/proc.go runtime.proc1.go
		// var buildVersion = sys.TheVersion
		Address sys_the_version_addr=null;
		// "go1."
		byte[] version_head=new byte[] {(byte)0x67, (byte)0x6f, (byte)0x31, (byte)0x2e};
		while(true) {
			sys_the_version_addr=go_bin.find_memory(sys_the_version_addr, version_head, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff});
			if(sys_the_version_addr==null) {
				break;
			}

			String str=go_bin.read_string(sys_the_version_addr, 15);
			Optional<String> sys_the_version_opt=GolangVersionExtractor.extract_go_version(str);
			if(sys_the_version_opt.isEmpty()) {
				sys_the_version_addr=sys_the_version_addr.add(4);
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
				string_struct_addr=go_bin.find_memory(string_struct_addr, addr_bytes, addr_mask);
				if(string_struct_addr==null) {
					break;
				}
				if(check_string_struct(string_struct_addr, sys_the_version_opt.get())) {
					return sys_the_version_opt;
				}
				string_struct_addr=string_struct_addr.add(4);
			}
			sys_the_version_addr=sys_the_version_addr.add(4);
		}
		return Optional.empty();
	}

	private boolean check_string_struct(Address string_struct_addr, String sys_the_version) {
		long size=go_bin.get_address_value(string_struct_addr.add(go_bin.get_pointer_size()), go_bin.get_pointer_size());
		if(size!=sys_the_version.length()) {
			return false;
		}

		// runtime/proc.go
		boolean badmorestackg0Msg=false;
		boolean badmorestackgsignalMsg=false;
		for(int i=-2; i<3; i++) {
			String around_str=go_bin.read_string_struct(string_struct_addr.add(go_bin.get_pointer_size()*2*i), go_bin.get_pointer_size());
			if(around_str==null) {
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
