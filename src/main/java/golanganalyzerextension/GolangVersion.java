package golanganalyzerextension;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import ghidra.program.model.address.Address;

public class GolangVersion {
	private static final String GO_VERSION_PATTERN="go\\d+(\\.\\d+(\\.\\d+)?)?(beta\\d+|rc\\d+)?";

	private GolangBinary go_bin;

	public GolangVersion(GolangBinary go_bin) {
		this.go_bin=go_bin;

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
		// sys.TheVersion
		Address sys_the_version_addr=null;
		// "go1."
		byte[] version_head=new byte[] {(byte)0x67, (byte)0x6f, (byte)0x31, (byte)0x2e};
		while(true) {
			sys_the_version_addr=go_bin.find_memory(sys_the_version_addr, version_head, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff});
			if(sys_the_version_addr==null) {
				break;
			}

			String str=go_bin.read_string(sys_the_version_addr, 15);
			Optional<String> go_version_opt=extract_go_version(str);
			if(go_version_opt.isEmpty()) {
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
				if(size==go_version_opt.get().length()) {
					return Optional.ofNullable(go_version_opt.get());
				}
				string_struct_addr=string_struct_addr.add(4);
			}
			sys_the_version_addr=sys_the_version_addr.add(4);
		}
		return Optional.empty();
	}
}
