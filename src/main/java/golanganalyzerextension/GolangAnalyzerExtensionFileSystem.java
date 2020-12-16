package golanganalyzerextension;

import java.io.*;
import java.util.*;

import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.bin.ByteProviderInputStream;
import ghidra.formats.gfilesystem.*;
import ghidra.formats.gfilesystem.annotations.FileSystemInfo;
import ghidra.formats.gfilesystem.factory.GFileSystemFactoryFull;
import ghidra.formats.gfilesystem.factory.GFileSystemProbeFull;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;

/**
 * TODO: Provide class-level documentation that describes what this file system does.
 */
@FileSystemInfo(type = "fstypegoeshere", // ([a-z0-9]+ only)
		description = "File system description goes here", factory = GolangAnalyzerExtensionFileSystem.MyFileSystemFactory.class)
public class GolangAnalyzerExtensionFileSystem implements GFileSystem {

	private final FSRLRoot fsFSRL;
	private FileSystemIndexHelper<MyMetadata> fsih;
	private FileSystemRefManager refManager = new FileSystemRefManager(this);

	private ByteProvider provider;

	/**
	 * File system constructor.
	 * 
	 * @param fsFSRL The root {@link FSRL} of the file system.
	 * @param provider The file system provider.
	 */
	public GolangAnalyzerExtensionFileSystem(FSRLRoot fsFSRL, ByteProvider provider) {
		this.fsFSRL = fsFSRL;
		this.provider = provider;
		this.fsih = new FileSystemIndexHelper<>(this, fsFSRL);
	}

	/**
	 * Mounts (opens) the file system.
	 * 
	 * @param monitor A cancellable task monitor.
	 */
	public void mount(TaskMonitor monitor) {
		monitor.setMessage("Opening " + GolangAnalyzerExtensionFileSystem.class.getSimpleName() + "...");

		// TODO: Customize how things in the file system are stored.  The following should be 
		// treated as pseudo-code.
		for (MyMetadata metadata : new MyMetadata[10]) {
			if (monitor.isCancelled()) {
				break;
			}
			fsih.storeFile(metadata.path, fsih.getFileCount(), false, metadata.size, metadata);
		}
	}

	@Override
	public void close() throws IOException {
		refManager.onClose();
		if (provider != null) {
			provider.close();
			provider = null;
		}
		fsih.clear();
	}

	@Override
	public String getName() {
		return fsFSRL.getContainer().getName();
	}

	@Override
	public FSRLRoot getFSRL() {
		return fsFSRL;
	}

	@Override
	public boolean isClosed() {
		return provider == null;
	}

	@Override
	public int getFileCount() {
		return fsih.getFileCount();
	}

	@Override
	public FileSystemRefManager getRefManager() {
		return refManager;
	}

	@Override
	public GFile lookup(String path) throws IOException {
		return fsih.lookup(path);
	}

	@Override
	public InputStream getInputStream(GFile file, TaskMonitor monitor)
			throws IOException, CancelledException {

		// TODO: Get an input stream for a file.  The following is an example of how the metadata
		// might be used to get an input stream from a stored provider offset.
		MyMetadata metadata = fsih.getMetadata(file);
		return (metadata != null)
				? new ByteProviderInputStream(provider, metadata.offset, metadata.size)
				: null;
	}

	@Override
	public List<GFile> getListing(GFile directory) throws IOException {
		return fsih.getListing(directory);
	}

	@Override
	public String getInfo(GFile file, TaskMonitor monitor) {
		MyMetadata metadata = fsih.getMetadata(file);
		return (metadata == null) ? null : FSUtilities.infoMapToString(getInfoMap(metadata));
	}

	public Map<String, String> getInfoMap(MyMetadata metadata) {
		Map<String, String> info = new LinkedHashMap<>();

		// TODO: Customize information about a file system entry.  The following is sample
		// information that might be useful.
		info.put("Name", metadata.name);
		info.put("Size",
			"" + Long.toString(metadata.size) + ", 0x" + Long.toHexString(metadata.size));
		return info;
	}

	// TODO: Customize for the real file system.
	public static class MyFileSystemFactory
			implements GFileSystemFactoryFull<GolangAnalyzerExtensionFileSystem>, GFileSystemProbeFull {

		@Override
		public GolangAnalyzerExtensionFileSystem create(FSRL containerFSRL, FSRLRoot targetFSRL,
				ByteProvider byteProvider, File containerFile, FileSystemService fsService,
				TaskMonitor monitor) throws IOException, CancelledException {

			GolangAnalyzerExtensionFileSystem fs = new GolangAnalyzerExtensionFileSystem(targetFSRL, byteProvider);
			fs.mount(monitor);
			return fs;
		}

		@Override
		public boolean probe(FSRL containerFSRL, ByteProvider byteProvider, File containerFile,
				FileSystemService fsService, TaskMonitor monitor)
				throws IOException, CancelledException {

			// TODO: Quickly and efficiently examine the bytes in 'byteProvider' to determine if 
			// it's a valid file system.  If it is, return true. 

			return false;
		}
	}

	// TODO: Customize with metadata from files in the real file system.  This is just a stub.
	// The elements of the file system will most likely be modeled by Java classes external to this
	// file.
	private static class MyMetadata {
		private String name;
		private String path;
		private long offset;
		private long size;
	}
}
