import static org.junit.Assert.assertEquals;

import java.lang.reflect.Field;
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
import golanganalyzerextension.GolangVersion;

public class GolangVersionTest extends AbstractGhidraHeadlessIntegrationTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_extract_go_version_params")
	public void test_extract_go_version(String expected, String data) throws Exception {
		initialize(new HashMap<String, String>());
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		GolangVersion go_version=new GolangVersion(go_bin);

		assertEquals(go_version.extract_go_version(data), Optional.ofNullable(expected));
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

	@ParameterizedTest
	@MethodSource("test_find_sys_the_version_params")
	public void test_find_sys_the_version(String expected, int pointer_size, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		GolangVersion go_version=new GolangVersion(go_bin);
		Field field=GolangBinary.class.getDeclaredField("pointer_size");
		field.setAccessible(true);
		field.set(go_bin, pointer_size);

		assertEquals(go_version.find_sys_the_version(), Optional.ofNullable(expected));
	}

	static Stream<Arguments> test_find_sys_the_version_params() throws Throwable {
		return Stream.of(
				Arguments.of("go1.8.7", 4, new HashMap<String, String>(){{
					put("0x0811bed0", "7f410d08 07000000");
					put("0x080d4170", "346673202020202067637472616365676f312e382e3767732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of(null, 4, new HashMap<String, String>(){{
					put("0x0811bed0", "00410d08 07000000");
					put("0x080d4170", "346673202020202067637472616365676f312e382e3767732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of(null, 4, new HashMap<String, String>(){{
					put("0x0811bed0", "7f410d08 0f000000");
					put("0x080d4170", "346673202020202067637472616365676f312e382e3767732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of(null, 4, new HashMap<String, String>(){{
					put("0x080d4170", "346673202020202067637472616365676f312e382e3767732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of(null, 4, new HashMap<String, String>(){{
				}}),
				Arguments.of("go1.8rc2", 8, new HashMap<String, String>(){{
					put("0x0050c640", "2e4f4b0000000000 0800000000000000");
					put("0x04b4f2e", "676f312e3872633267732020202020206e6578745f67633d6e6f20616e6f646572313020202020207231312020202020");
				}}),
				Arguments.of(null, 8, new HashMap<String, String>(){{
					put("0x0050c640", "004f4b0000000000 0800000000000000");
					put("0x04b4f2e", "676f312e3872633267732020202020206e6578745f67633d6e6f20616e6f646572313020202020207231312020202020");
				}}),
				Arguments.of(null, 8, new HashMap<String, String>(){{
					put("0x0050c640", "2e4f4b0000000000 0900000000000000");
					put("0x04b4f2e", "676f312e3872633267732020202020206e6578745f67633d6e6f20616e6f646572313020202020207231312020202020");
				}}),
				Arguments.of(null, 8, new HashMap<String, String>(){{
					put("0x04b4f2e", "676f312e3872633267732020202020206e6578745f67633d6e6f20616e6f646572313020202020207231312020202020");
				}}),
				Arguments.of(null, 8, new HashMap<String, String>(){{
				}})
			);
	}
}
