package golanganalyzerextension.version;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import golanganalyzerextension.exceptions.InvalidGolangVersionFormatException;
import golanganalyzerextension.gobinary.GolangBinary;

public class GolangVersionExtractor {
	private static final String DEFAULT_GO_VERSION="go0.0.0";

	private GolangBinary init_go_bin;

	private String go_version;

	public GolangVersionExtractor(GolangBinary init_go_bin) {
		this.init_go_bin=init_go_bin;
		go_version=DEFAULT_GO_VERSION;
	}

	public GolangVersion get_go_version() {
		try {
			return new GolangVersion(go_version);
		} catch(InvalidGolangVersionFormatException e) {
			return new GolangVersion(DEFAULT_GO_VERSION);
		}
	}

	public void scan() {
		int pointer_size_list[]= {4, 8};
		for(int pointer_size : pointer_size_list) {
			GolangBinary tmp_go_bin=new GolangBinary(init_go_bin, null, null, null, null, null, 0, 0, pointer_size, null);

			if(scan_build_info(tmp_go_bin)) {
				return;
			}

			if(scan_sys_the_version(tmp_go_bin)) {
				return;
			}
		}
	}

	private boolean scan_build_info(GolangBinary go_bin) {
		GolangBuildInfo go_build_info=new GolangBuildInfo(go_bin);
		Optional<String> go_version_opt=go_build_info.get_go_version();
		if(go_version_opt.isEmpty()) {
			return false;
		}
		if(!GolangVersion.is_go_version(go_version_opt.get())) {
			return false;
		}
		go_version=go_version_opt.get();
		return true;
	}

	private boolean scan_sys_the_version(GolangBinary go_bin) {
		SysTheVersion sys_the_version=new SysTheVersion(go_bin);
		Optional<String> go_version_opt=sys_the_version.get_go_version();
		if(go_version_opt.isEmpty()) {
			return false;
		}
		if(!GolangVersion.is_go_version(go_version_opt.get())) {
			return false;
		}
		go_version=go_version_opt.get();
		return true;
	}

	public static Optional<String> extract_go_version(String data) {
		Pattern p = Pattern.compile(GolangVersion.get_version_pattern());
		Matcher m = p.matcher(data);
		if(m.find()) {
			return Optional.ofNullable(m.group());
		}
		return Optional.empty();
	}
}
