package golanganalyzerextension;

import ghidra.framework.options.Options;

public class AnalyzerOption {
	private static final String RENAME_FUNC="Rename functions";
	private static final String RENAME_FUNC_DESC="Rename functions.";
	private boolean rename_option;
	private static final String CORRECT_ARG="Correct arguments";
	private static final String CORRECT_ARG_DESC="Correct function arguments.";
	private boolean param_option;
	private static final String ADD_COMMENT="Add function comments";
	private static final String ADD_COMMENT_DESC="Add source file and line information to comments.";
	private boolean comment_option;
	private static final String DISASM_FUNC="Disassemble functions";
	private static final String DISASM_FUNC_DESC="Disassemble functions.";
	private boolean disasm_option;

	private static final String ADD_DATATYPE="Add data types";
	private static final String ADD_DATATYPE_DESC="Add golang data types to Data Type Manager.";
	private boolean datatype_option;

	private static final String SEARCH_STRING="Search strings";
	private static final String SEARCH_STRING_DESC="Search golang strings, add labels and set data types";
	private boolean string_option;

	private static final String DEBUG_MODE="Use debug mode";
	private static final String DEBUG_MODE_DESC="Enable logging.";
	private boolean debugmode_option;

	public AnalyzerOption() {
		set_default();
	}

	private void set_default() {
		rename_option=true;
		param_option=true;
		comment_option=true;
		disasm_option=false;
		datatype_option=true;
		string_option=true;
		debugmode_option=false;
	}

	public boolean get_rename() {
		return rename_option;
	}

	public boolean get_param() {
		return param_option;
	}

	public boolean get_comment() {
		return comment_option;
	}

	public boolean get_disasm() {
		return disasm_option;
	}

	public boolean get_datatype() {
		return datatype_option;
	}

	public boolean get_string() {
		return string_option;
	}

	public boolean get_debugmode() {
		return debugmode_option;
	}

	public void register(Options options) {
		options.registerOption(RENAME_FUNC, rename_option, null, RENAME_FUNC_DESC);
		options.registerOption(CORRECT_ARG, param_option, null, CORRECT_ARG_DESC);
		options.registerOption(ADD_COMMENT, comment_option, null, ADD_COMMENT_DESC);
		options.registerOption(DISASM_FUNC, disasm_option, null, DISASM_FUNC_DESC);
		options.registerOption(ADD_DATATYPE, datatype_option, null, ADD_DATATYPE_DESC);
		options.registerOption(SEARCH_STRING, string_option, null, SEARCH_STRING_DESC);
		options.registerOption(DEBUG_MODE, debugmode_option, null, DEBUG_MODE_DESC);
	}

	public void change(Options options) {
		rename_option=options.getBoolean(RENAME_FUNC, rename_option);
		param_option=options.getBoolean(CORRECT_ARG, param_option);
		comment_option=options.getBoolean(ADD_COMMENT, comment_option);
		disasm_option=options.getBoolean(DISASM_FUNC, disasm_option);
		datatype_option=options.getBoolean(ADD_DATATYPE, datatype_option);
		string_option=options.getBoolean(SEARCH_STRING, string_option);
		debugmode_option=options.getBoolean(DEBUG_MODE, debugmode_option);
	}
}
