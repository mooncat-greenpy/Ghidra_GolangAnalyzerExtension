import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.util.Iterator;
import java.util.List;

import generic.lsh.vector.LSHVectorFactory;
import ghidra.app.script.GhidraScript;
import ghidra.features.base.values.GhidraValuesMap;
import ghidra.features.bsim.query.*;
import ghidra.features.bsim.query.FunctionDatabase.BSimError;
import ghidra.features.bsim.query.FunctionDatabase.ErrorCategory;
import ghidra.features.bsim.query.description.DatabaseInformation;
import ghidra.features.bsim.query.description.DescriptionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager;
import ghidra.features.bsim.query.file.BSimH2FileDBConnectionManager.BSimH2FileDataSource;
import ghidra.features.bsim.query.protocol.*;
import ghidra.framework.model.DomainFile;
import ghidra.framework.protocol.ghidra.GhidraURL;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionManager;
import ghidra.util.MessageType;

public class AddGolangProgramToH2BSimDatabaseScript extends GhidraScript {

	private static final String DATABASE = "H2 Database";

	@Override
	protected void run() throws Exception {
		List<Function> main_func = currentProgram.getListing().getGlobalFunctions("main.main");
		if (main_func.size() == 1) {
			currentProgram.getListing().removeFunction(main_func.get(0).getEntryPoint());
		}

		if (currentProgram == null) {
			return;
		}


		File h2DbFile = new File("dump/golang.mv.db");
		BSimServerInfo serverInfo = new BSimServerInfo(h2DbFile.getAbsolutePath());

		BSimH2FileDataSource existingBDS =
			BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
		if (existingBDS != null && existingBDS.getActiveConnections() > 0) {
			return;
		}

		try (FunctionDatabase h2Database = BSimClientFactory.buildClient(serverInfo, false)) {

			h2Database.initialize();
			DatabaseInformation dbInfo = h2Database.getInfo();

			LSHVectorFactory vectorFactory = h2Database.getLSHVectorFactory();
			GenSignatures gensig = null;
			try {
				gensig = new GenSignatures(dbInfo.trackcallgraph);
				gensig.setVectorFactory(vectorFactory);
				gensig.addExecutableCategories(dbInfo.execats);
				gensig.addFunctionTags(dbInfo.functionTags);
				gensig.addDateColumnName(dbInfo.dateColumnName);

				DomainFile dFile = currentProgram.getDomainFile();
				URL fileURL = dFile.getSharedProjectURL(null);
				if (fileURL == null) {
					fileURL = dFile.getLocalProjectURL(null);
				}
				if (fileURL == null) {
					return;
				}

				String path = GhidraURL.getProjectPathname(fileURL);
				int lastSlash = path.lastIndexOf('/');
				path = lastSlash == 0 ? "/" : path.substring(0, lastSlash);

				URL normalizedProjectURL = GhidraURL.getProjectURL(fileURL);
				String repo = normalizedProjectURL.toExternalForm();

				gensig.openProgram(this.currentProgram, null, null, null, repo, path);
				final FunctionManager fman = currentProgram.getFunctionManager();
				final Iterator<Function> iter = fman.getFunctions(true);
				gensig.scanFunctions(iter, fman.getFunctionCount(), monitor);
				final DescriptionManager manager = gensig.getDescriptionManager();

				manager.listAllFunctions().forEachRemaining(fd -> fd.sortCallgraph());

				InsertRequest insertreq = new InsertRequest();
				insertreq.manage = manager;
				if (insertreq.execute(h2Database) == null) {
					BSimError lastError = h2Database.getLastError();
					if ((lastError.category == ErrorCategory.Format) ||
						(lastError.category == ErrorCategory.Nonfatal)) {
						return;
					}
					throw new IOException(currentProgram.getName() + ": " + lastError.message);
				}
			}
			finally {
				if (gensig != null) {
					gensig.dispose();
				}
			}

		}
		finally {
			if (existingBDS == null) {
				BSimH2FileDataSource bds =
					BSimH2FileDBConnectionManager.getDataSourceIfExists(serverInfo);
				if (bds != null) {
					bds.dispose();
				}
			}
		}
	}
}
