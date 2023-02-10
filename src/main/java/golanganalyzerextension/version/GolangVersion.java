package golanganalyzerextension.version;

import golanganalyzerextension.exceptions.InvalidGolangVersionFormatException;

public class GolangVersion {
	private static final String GO_VERSION_PATTERN="go\\d+(\\.\\d+(\\.\\d+)?)?(beta\\d+|rc\\d+)?";
	// major minor patch
	private static final int PART_NUM=3;
	// normal rc beta
	private static final int VALUE_NUM=2;
	private static final int RC_BASE=10000;
	private static final int BETA_BASE=1;
	private static final int RC_BETA_MAX_VALUE=99999999;

	private String version_str;
	private int[][] version_data;

	public GolangVersion(String go_version) throws InvalidGolangVersionFormatException {
		if(!is_go_version(go_version)) {
			throw new InvalidGolangVersionFormatException(String.format("Invalid Go version: str=%s", go_version));
		}
		version_str=go_version;
		version_data=new int[PART_NUM][VALUE_NUM];
		parse_version_str();
	}

	public static String get_version_pattern() {
		return GO_VERSION_PATTERN;
	}

	public static boolean is_go_version(String str) {
		return str.matches(GO_VERSION_PATTERN);
	}

	public String get_version_str() {
		return version_str;
	}

	public boolean eq(String go_version) throws InvalidGolangVersionFormatException {
		return compare(this, new GolangVersion(go_version))==0;
	}

	public boolean gt(String go_version) throws InvalidGolangVersionFormatException {
		return compare(this, new GolangVersion(go_version))>0;
	}

	public boolean lt(String go_version) throws InvalidGolangVersionFormatException {
		return compare(this, new GolangVersion(go_version))<0;
	}

	public boolean ge(String go_version) throws InvalidGolangVersionFormatException {
		return compare(this, new GolangVersion(go_version))>=0;
	}

	public boolean le(String go_version) throws InvalidGolangVersionFormatException {
		return compare(this, new GolangVersion(go_version))<=0;
	}

	public void set_version_str(String str) {
		version_str=str;
	}

	private int compare(GolangVersion cmp1, GolangVersion cmp2) {
		for(int i=0; i<PART_NUM; i++) {
			for(int j=0; j<VALUE_NUM; j++) {
				if(cmp1.version_data[i][j]>cmp2.version_data[i][j]) {
					return 1;
				} else if(cmp1.version_data[i][j]<cmp2.version_data[i][j]) {
					return -1;
				}
			}
		}
		return 0;
	}

	private void parse_version_str() throws InvalidGolangVersionFormatException {
		if(version_str.length()<=2 || !version_str.startsWith("go")) {
			throw new InvalidGolangVersionFormatException("Not start with \"go\".");
		}
		String[] split_str=version_str.substring(2).split("\\.");
		if(split_str.length>PART_NUM) {
			throw new InvalidGolangVersionFormatException("Too many \".\".");
		}
		for(int i=0; i<split_str.length; i++) {
			version_data[i][0]=get_ver_value(split_str[i]);
			version_data[i][1]=get_rc_beta_value(split_str[i]);
		}
	}

	private int get_ver_value(String str) throws InvalidGolangVersionFormatException {
		try {
			if(str.contains("rc")) {
				return Integer.valueOf(str.split("rc")[0]);
			}
			if(str.contains("beta")) {
				return Integer.valueOf(str.split("beta")[0]);
			}
			return Integer.valueOf(str);
		} catch(NumberFormatException e) {
			throw new InvalidGolangVersionFormatException(str+" is invalid.");
		}		
	}

	private int get_rc_beta_value(String str) throws InvalidGolangVersionFormatException {
		try {
			if(str.contains("rc")) {
				return Integer.valueOf(str.split("rc")[1])*RC_BASE;
			}
			if(str.contains("beta")) {
				return Integer.valueOf(str.split("beta")[1])*BETA_BASE;
			}
			return RC_BETA_MAX_VALUE;
		} catch(NumberFormatException e) {
			throw new InvalidGolangVersionFormatException(str+" is invalid.");
		}		
	}
}
