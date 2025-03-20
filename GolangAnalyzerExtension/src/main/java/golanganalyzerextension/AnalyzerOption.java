package golanganalyzerextension;

import ghidra.framework.options.Options;
import golanganalyzerextension.guess.GuessedConfidence;

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
	private static final String SEARCH_STRING_DESC="Search golang strings, add labels and set data types.";
	private boolean string_option;

	private static final String DEBUG_MODE="Use debug mode";
	private static final String DEBUG_MODE_DESC="Enable logging.";
	private boolean debugmode_option;

	private static final String PCHEADER_ADDR="PcHeader Address";
	private static final String PCHEADER_ADDR_DESC="Specify the address of PcHeader (optional).";
	private String pcheader_addr_option;
	private static final String GOLANG_VERSION="Golang version";
	private static final String GOLANG_VERSION_DESC="Specify the Go version to use for analysis (optional).";
	private String go_version_option;

	private static final String GUESS_FUNC="Guess function names";
	private static final String GUESS_FUNC_DESC="Predicting the function name via pattern matching.";
	private boolean guess_func_option;
	private static final String GUESS_CONFIDENCE_FUNC="Confidence of the guess";
	private static final String GUESS_CONFIDENCE_FUNC_DESC="Confidence of function name guess results.";
	private GuessedConfidence guess_confidence_func_option;

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
		pcheader_addr_option="";
		go_version_option="";
		guess_func_option=false;
		guess_confidence_func_option=GuessedConfidence.MEDIUM;
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

	public String get_pcheader_addr_str() {
		return pcheader_addr_option;
	}

	public String get_go_version() {
		return go_version_option;
	}

	public boolean get_guess_func() {
		return guess_func_option;
	}

	public GuessedConfidence get_guess_confidence_func() {
		return guess_confidence_func_option;
	}

	public void register(Options options) {
		options.registerOption(RENAME_FUNC, rename_option, null, RENAME_FUNC_DESC);
		options.registerOption(CORRECT_ARG, param_option, null, CORRECT_ARG_DESC);
		options.registerOption(ADD_COMMENT, comment_option, null, ADD_COMMENT_DESC);
		options.registerOption(DISASM_FUNC, disasm_option, null, DISASM_FUNC_DESC);
		options.registerOption(ADD_DATATYPE, datatype_option, null, ADD_DATATYPE_DESC);
		options.registerOption(SEARCH_STRING, string_option, null, SEARCH_STRING_DESC);
		options.registerOption(DEBUG_MODE, debugmode_option, null, DEBUG_MODE_DESC);
		options.registerOption(PCHEADER_ADDR, pcheader_addr_option, null, PCHEADER_ADDR_DESC);
		options.registerOption(GOLANG_VERSION, go_version_option, null, GOLANG_VERSION_DESC);
		options.registerOption(GUESS_FUNC, guess_func_option, null, GUESS_FUNC_DESC);
		options.registerOption(GUESS_CONFIDENCE_FUNC, guess_confidence_func_option, null, GUESS_CONFIDENCE_FUNC_DESC);
	}

	public void change(Options options) {
		rename_option=options.getBoolean(RENAME_FUNC, rename_option);
		param_option=options.getBoolean(CORRECT_ARG, param_option);
		comment_option=options.getBoolean(ADD_COMMENT, comment_option);
		disasm_option=options.getBoolean(DISASM_FUNC, disasm_option);
		datatype_option=options.getBoolean(ADD_DATATYPE, datatype_option);
		string_option=options.getBoolean(SEARCH_STRING, string_option);
		debugmode_option=options.getBoolean(DEBUG_MODE, debugmode_option);
		pcheader_addr_option=options.getString(PCHEADER_ADDR, pcheader_addr_option);
		go_version_option=options.getString(GOLANG_VERSION, go_version_option);
		guess_func_option=options.getBoolean(GUESS_FUNC, guess_func_option);
		guess_confidence_func_option=options.getEnum(GUESS_CONFIDENCE_FUNC, guess_confidence_func_option);
	}
}
