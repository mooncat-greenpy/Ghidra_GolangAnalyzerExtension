package golanganalyzerextension;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;

public class GolangVersion {
	private static final String DEFAULT_GO_VERSION="go0.0.0";
	private static final String GO_VERSION_PATTERN="go\\d+(\\.\\d+(\\.\\d+)?)?(beta\\d+|rc\\d+)?";

	private GolangBinary go_bin;

	private String go_version;

	public GolangVersion(GolangBinary go_bin) {
		this.go_bin=go_bin;
		go_version=DEFAULT_GO_VERSION;
	}

	public String get_go_version() {
		return go_version;
	}

	public void scan() {
		GolangBuildInfo go_build_info=new GolangBuildInfo(go_bin);
		go_build_info.get_go_version().ifPresent(s -> go_version=s);;
		if(!go_version.equals(DEFAULT_GO_VERSION)) {
			return;
		}

		find_sys_the_version().ifPresent(s -> go_version=s);
	}

	public boolean is_go_version(String str) {
		return str.matches(GO_VERSION_PATTERN);
	}

	public Optional<String> extract_go_version(String data) {
		Pattern p = Pattern.compile(GO_VERSION_PATTERN);
		Matcher m = p.matcher(data);
		if(m.find()) {
			return Optional.ofNullable(m.group());
		}
		return Optional.empty();
	}

	public Optional<String> find_sys_the_version() {
		// runtime/proc.go
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
			Optional<String> sys_the_version_opt=extract_go_version(str);
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
				long size=go_bin.get_address_value(string_struct_addr.add(go_bin.get_pointer_size()), go_bin.get_pointer_size());
				if(size==sys_the_version_opt.get().length()) {
					return sys_the_version_opt;
				}
				string_struct_addr=string_struct_addr.add(4);
			}
			sys_the_version_addr=sys_the_version_addr.add(4);
		}
		return Optional.empty();
	}

	public int compare_go_version(String cmp_go_version) {
		return compare_go_version(cmp_go_version, go_version.length()>2?go_version:DEFAULT_GO_VERSION);
	}

	public int compare_go_version(String cmp_go_version1, String cmp_go_version2) {
		String cmp1=cmp_go_version1.substring(2);
		String cmp2=cmp_go_version2.substring(2);
		String[] sp_cmp1=cmp1.split("\\.");
		String[] sp_cmp2=cmp2.split("\\.");

		int cmp1_major=0;
		int cmp2_major=0;
		if(sp_cmp1.length!=0) {
			cmp1_major=Integer.valueOf(sp_cmp1[0]);
		}
		if(sp_cmp2.length!=0) {
			cmp2_major=Integer.valueOf(sp_cmp2[0]);
		}

		if(cmp1_major>cmp2_major) {
			return 1;
		}else if(cmp1_major<cmp2_major) {
			return -1;
		}

		int cmp1_minor=0;
		int cmp1_patch=0;
		boolean cmp1_beta=false;
		boolean cmp1_rc=false;
		if(sp_cmp1.length>1 && sp_cmp1[1].contains("beta")) {
			cmp1_beta=true;
			String[] tmp=sp_cmp1[1].split("beta");
			if(tmp.length>1) {
				cmp1_minor=Integer.valueOf(tmp[0]);
				cmp1_patch=Integer.valueOf(tmp[1]);
			}
		}else if(sp_cmp1.length>1 && sp_cmp1[1].contains("rc")) {
			cmp1_rc=true;
			String[] tmp=sp_cmp1[1].split("rc");
			if(tmp.length>1) {
				cmp1_minor=Integer.valueOf(tmp[0]);
				cmp1_patch=Integer.valueOf(tmp[1]);
			}
		}else if(sp_cmp1.length>1) {
			cmp1_minor=Integer.valueOf(sp_cmp1[1]);
			if(sp_cmp1.length>2) {
				cmp1_patch=Integer.valueOf(sp_cmp1[2]);
			}
		}
		int cmp2_minor=0;
		int cmp2_patch=0;
		boolean cmp2_beta=false;
		boolean cmp2_rc=false;
		if(sp_cmp2.length>1 && sp_cmp2[1].contains("beta")) {
			cmp2_beta=true;
			String[] tmp=sp_cmp2[1].split("beta");
			if(tmp.length>1) {
				cmp2_minor=Integer.valueOf(tmp[0]);
				cmp2_patch=Integer.valueOf(tmp[1]);
			}
		}else if(sp_cmp2.length>1 && sp_cmp2[1].contains("rc")) {
			cmp2_rc=true;
			String[] tmp=sp_cmp2[1].split("rc");
			if(tmp.length>1) {
				cmp2_minor=Integer.valueOf(tmp[0]);
				cmp2_patch=Integer.valueOf(tmp[1]);
			}
		}else if(sp_cmp2.length>1) {
			cmp2_minor=Integer.valueOf(sp_cmp2[1]);
			if(sp_cmp2.length>2) {
				cmp2_patch=Integer.valueOf(sp_cmp2[2]);
			}
		}
		if(cmp1_minor>cmp2_minor) {
			return 1;
		}else if(cmp1_minor<cmp2_minor) {
			return -1;
		}
		if(!cmp1_beta && cmp2_beta) {
			return 1;
		}else if(cmp1_beta && !cmp2_beta) {
			return -1;
		}
		if(!cmp1_rc && cmp2_rc) {
			return 1;
		}else if(cmp1_rc && !cmp2_rc) {
			return -1;
		}
		if(cmp1_patch>cmp2_patch) {
			return 1;
		}else if(cmp1_patch<cmp2_patch) {
			return -1;
		}
		return 0;
	}
}
