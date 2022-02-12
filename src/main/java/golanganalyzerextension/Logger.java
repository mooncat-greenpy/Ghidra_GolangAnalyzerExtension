package golanganalyzerextension;

import ghidra.app.util.importer.MessageLog;

public class Logger {
	static MessageLog logger=null;
	static boolean mode=false;

	private Logger(MessageLog log, boolean debugmode) {
		logger=log;
		mode=debugmode;
	}

	public static void set_logger(MessageLog log, boolean debugmode) {
		new Logger(log,debugmode);
	}

	public static void append_message(String str) {
		if (logger==null) {
			return;
		}
		if(mode) {
			logger.appendMsg(str);
		}
	}
}