package golanganalyzerextension.version;

import java.util.Optional;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import golanganalyzerextension.GolangBinary;
import golanganalyzerextension.GolangBuildInfo;
import golanganalyzerextension.SysTheVersion;

public class GolangVersionExtractor {
	private static final String DEFAULT_GO_VERSION="go0.0.0";

	private GolangBinary go_bin;

	private String go_version;

	public GolangVersionExtractor(GolangBinary go_bin) {
		this.go_bin=go_bin;
		go_version=DEFAULT_GO_VERSION;
	}

	public GolangVersion get_go_version() {
		return new GolangVersion(go_version);
	}

	public void scan() {
		int pointer_size_list[]= {4, 8};
		for(int pointer_size : pointer_size_list) {
			GolangBinary tmp_go_bin=new GolangBinary(go_bin, null, null, null, null, null, 0, 0, pointer_size, null);
			GolangBuildInfo go_build_info=new GolangBuildInfo(tmp_go_bin);
			go_build_info.get_go_version().ifPresent(s -> {if(GolangVersion.is_go_version(s)) {go_version=s;}});;
			if(!go_version.equals(DEFAULT_GO_VERSION)) {
				return;
			}

			SysTheVersion sys_the_version=new SysTheVersion(tmp_go_bin);
			sys_the_version.get_go_version().ifPresent(s -> {if(GolangVersion.is_go_version(s)) {go_version=s;}});
			if(!go_version.equals(DEFAULT_GO_VERSION)) {
				return;
			}
		}
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
