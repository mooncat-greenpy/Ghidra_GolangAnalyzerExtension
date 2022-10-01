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
import golanganalyzerextension.GolangBinary;
import golanganalyzerextension.SysTheVersion;

public class SysTheVersionTest extends AbstractGhidraHeadlessIntegrationTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}


	@ParameterizedTest
	@MethodSource("test_sys_the_version_params")
	public void test_sys_the_version(String expected, int pointer_size, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(new GolangBinary(program, TaskMonitor.DUMMY), null, null, null, null, null, 0, 0, pointer_size, null);

		SysTheVersion sys_the_version=new SysTheVersion(go_bin);

		assertEquals(sys_the_version.get_go_version(), Optional.ofNullable(expected));
	}

	static Stream<Arguments> test_sys_the_version_params() throws Throwable {
		return Stream.of(
				Arguments.of("go1.8.7", 4, new HashMap<String, String>(){{
					put("0x0811bec0", "53630d08 17000000 32710d08 1c000000 7f410d08 07000000");
					put("0x080d6353", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x080d7132", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of(null, 4, new HashMap<String, String>(){{
					put("0x0811bec0", "53630d08 17000000 32710d08 1c000000 7f410d08 07000000");
					put("0x004b7cdc", "3131313131313131313131313131313131313131313131");
					put("0x080d7132", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of(null, 4, new HashMap<String, String>(){{
					put("0x0811bec0", "53630d08 17000000 32710d08 1c000000 7f410d08 07000000");
					put("0x080d6353", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x004b8f17", "31313131313131313131313131313131313131313131313131313131");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of(null, 4, new HashMap<String, String>(){{
					put("0x0811bec0", "53630d08 17000000 32710d08 1c000000 00410d08 07000000");
					put("0x080d6353", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x080d7132", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of(null, 4, new HashMap<String, String>(){{
					put("0x0811bec0", "53630d08 17000000 32710d08 1c000000 7f410d08 0f000000");
					put("0x080d6353", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x080d7132", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of(null, 4, new HashMap<String, String>(){{
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of(null, 4, new HashMap<String, String>(){{
				}}),
				Arguments.of("go1.8rc2", 8, new HashMap<String, String>(){{
					put("0x0050c620", "dc7c4b0000000000 1700000000000000 178f4b0000000000 1c00000000000000 2e4f4b0000000000 0800000000000000");
					put("0x004b7cdc", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x004b8f17", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x004b4f20", "2020202020206673202020202020 676f312e38726332 67732020202020206e6578745f67633d6e6f20616e6f64657231");
				}}),
				Arguments.of(null, 8, new HashMap<String, String>(){{
					put("0x0050c620", "dc7c4b0000000000 1700000000000000 178f4b0000000000 1c00000000000000 2e4f4b0000000000 0800000000000000");
					put("0x004b7cdc", "3131313131313131313131313131313131313131313131");
					put("0x004b8f17", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x004b4f20", "2020202020206673202020202020 676f312e38726332 67732020202020206e6578745f67633d6e6f20616e6f64657231");
				}}),
				Arguments.of(null, 8, new HashMap<String, String>(){{
					put("0x0050c620", "dc7c4b0000000000 1700000000000000 178f4b0000000000 1c00000000000000 2e4f4b0000000000 0800000000000000");
					put("0x004b7cdc", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x004b8f17", "31313131313131313131313131313131313131313131313131313131");
					put("0x004b4f20", "2020202020206673202020202020 676f312e38726332 67732020202020206e6578745f67633d6e6f20616e6f64657231");
				}}),
				Arguments.of(null, 8, new HashMap<String, String>(){{
					put("0x0050c620", "dc7c4b0000000000 1700000000000000 178f4b0000000000 1c00000000000000 004f4b0000000000 0800000000000000");
					put("0x004b7cdc", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x004b8f17", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x004b4f20", "2020202020206673202020202020 676f312e38726332 67732020202020206e6578745f67633d6e6f20616e6f64657231");
				}}),
				Arguments.of(null, 8, new HashMap<String, String>(){{
					put("0x0050c620", "dc7c4b0000000000 1700000000000000 178f4b0000000000 1c00000000000000 2e4f4b0000000000 0900000000000000");
					put("0x004b7cdc", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x004b8f17", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x004b4f20", "2020202020206673202020202020 676f312e38726332 67732020202020206e6578745f67633d6e6f20616e6f64657231");
				}}),
				Arguments.of(null, 8, new HashMap<String, String>(){{
					put("0x004b4f20", "2020202020206673202020202020 676f312e38726332 67732020202020206e6578745f67633d6e6f20616e6f64657231");
				}}),
				Arguments.of(null, 8, new HashMap<String, String>(){{
				}})
			);
	}
}
