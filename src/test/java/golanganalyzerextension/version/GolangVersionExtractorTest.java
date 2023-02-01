package golanganalyzerextension.version;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import golanganalyzerextension.gobinary.GolangBinary;

public class GolangVersionExtractorTest extends AbstractGhidraHeadlessIntegrationTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_get_go_version_params")
	public void test_get_go_version(String expected, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		GolangVersionExtractor go_version_extractor=new GolangVersionExtractor(go_bin);
		go_version_extractor.scan();
		GolangVersion go_version=go_version_extractor.get_go_version();

		assertEquals(go_version.get_version_str(), expected);
	}

	static Stream<Arguments> test_get_go_version_params() throws Throwable {
		return Stream.of(
				Arguments.of("go1.16.7", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 00 78725300 98725300 0000000000000000");
					put("0x537278", "d5f64a00 08000000");
					put("0x4af6d5", "676f312e31362e37");
					put("0x00537298", "bb834b00 60000000");
					put("0x004b83bb", "3077af0c9274080241e1c107e6d618e6 7061746809636f6d6d616e642d6c696e652d617267756d656e74730a6d6f6409636f6d6d616e642d6c696e652d617267756d656e74730928646576656c29090a f932433186182072008242104116d8f2");

					put("0x0811bed0", "7f410d08 07000000");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");

					put("0x00600000", "fbffffff 00 00 01 04 00000000");
					put("0x0060000c", "00104000 00200000");
					put("0x00602000", "00104000");
				}}),
				Arguments.of("go1.16.7", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 08 00 7872530000000000 9872530000000000");
					put("0x537278", "d5f64a0000000000 0800000000000000");
					put("0x4af6d5", "676f312e31362e37");
					put("0x00537298", "bb834b0000000000 6000000000000000");
					put("0x004b83bb", "3077af0c9274080241e1c107e6d618e6 7061746809636f6d6d616e642d6c696e652d617267756d656e74730a6d6f6409636f6d6d616e642d6c696e652d617267756d656e74730928646576656c29090a f932433186182072008242104116d8f2");

					put("0x0050c640", "2e4f4b0000000000 0800000000000000");
					put("0x04b4f20", "2020202020206673202020202020676f312e3872633267732020202020206e6578745f67633d6e6f20616e6f64657231");

					put("0x00600000", "fbffffff 00 00 01 08 0000000000000000");
					put("0x00600010", "0010400000000000 0020000000000000");
					put("0x00602000", "0010400000000000");
				}}),
				Arguments.of("go1.16.7", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 02 0000000000000000 0000000000000000 08 676f312e31362e37");

					put("0x0811bed0", "7f410d08 07000000");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");

					put("0x00600000", "fbffffff 00 00 01 04 00000000");
					put("0x0060000c", "00104000 00200000");
					put("0x00602000", "00104000");
				}}),
				Arguments.of("go1.8.7", new HashMap<String, String>(){{
					put("0x0811bec0", "53630d08 17000000 32710d08 1c000000 7f410d08 07000000");
					put("0x080d6353", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x080d7132", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");

					put("0x00600000", "fbffffff 00 00 01 04 00000000");
					put("0x0060000c", "00104000 00200000");
					put("0x00602000", "00104000");
				}}),
				Arguments.of("go1.8rc2", new HashMap<String, String>(){{
					put("0x0050c620", "dc7c4b0000000000 1700000000000000 178f4b0000000000 1c00000000000000 2e4f4b0000000000 0800000000000000");
					put("0x004b7cdc", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x004b8f17", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x004b4f20", "2020202020206673202020202020 676f312e38726332 67732020202020206e6578745f67633d6e6f20616e6f64657231");

					put("0x00600000", "fbffffff 00 00 01 08 0000000000000000");
					put("0x00600010", "0010400000000000 0020000000000000");
					put("0x00602000", "0010400000000000");
				}}),
				Arguments.of("go0.0.0", new HashMap<String, String>(){{
					put("0x00600000", "fbffffff 00 00 01 04 00000000");
					put("0x0060000c", "00104000 00200000");
					put("0x00602000", "00104000");
				}})
			);
	}

	@ParameterizedTest
	@MethodSource("test_extract_go_version_params")
	public void test_extract_go_version(String expected, String data) throws Exception {
		initialize(new HashMap<String, String>());

		assertEquals(GolangVersionExtractor.extract_go_version(data), Optional.ofNullable(expected));
	}

	static Stream<Arguments> test_extract_go_version_params() throws Throwable {
		return Stream.of(
				Arguments.of(null, "testgo"),
				Arguments.of("go1.8.7", "aaago1.8.7aaa"),
				Arguments.of("go1.8", "aaago1.8aaa"),
				Arguments.of("go1", "aaago1aaa"),
				Arguments.of("go1.8.7beta1", "aaago1.8.7beta1aaa"),
				Arguments.of("go1.8.7rc2", "aaago1.8.7rc2aaa"),
				Arguments.of("go1.8rc1", "aaago1.8rc1aaa"),
				Arguments.of("go1.8beta2", "aaago1.8beta2aaa"),
				Arguments.of("go1.8", "go1.8."),
				Arguments.of("go1.8", "go1.8beta"),
				Arguments.of("go1.8", "go1.8rc")
			);
	}

}
