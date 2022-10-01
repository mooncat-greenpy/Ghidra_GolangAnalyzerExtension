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
	@MethodSource("test_get_go_version_params")
	public void test_get_go_version(String expected, int pointer_size, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);
		Field field=GolangBinary.class.getDeclaredField("pointer_size");
		field.setAccessible(true);
		field.set(go_bin, pointer_size);

		GolangVersion go_version=new GolangVersion(go_bin);
		go_version.scan();

		assertEquals(go_version.get_go_version(), expected);
	}

	static Stream<Arguments> test_get_go_version_params() throws Throwable {
		return Stream.of(
				Arguments.of("go1.16.7", 4, new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 00 78725300 98725300 0000000000000000");
					put("0x537278", "d5f64a00 08000000");
					put("0x4af6d5", "676f312e31362e37");
					put("0x00537298", "bb834b00 60000000");
					put("0x004b83bb", "3077af0c9274080241e1c107e6d618e6 7061746809636f6d6d616e642d6c696e652d617267756d656e74730a6d6f6409636f6d6d616e642d6c696e652d617267756d656e74730928646576656c29090a f932433186182072008242104116d8f2");

					put("0x0811bed0", "7f410d08 07000000");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of("go1.16.7", 8, new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 08 00 7872530000000000 9872530000000000");
					put("0x537278", "d5f64a0000000000 0800000000000000");
					put("0x4af6d5", "676f312e31362e37");
					put("0x00537298", "bb834b0000000000 6000000000000000");
					put("0x004b83bb", "3077af0c9274080241e1c107e6d618e6 7061746809636f6d6d616e642d6c696e652d617267756d656e74730a6d6f6409636f6d6d616e642d6c696e652d617267756d656e74730928646576656c29090a f932433186182072008242104116d8f2");

					put("0x0050c640", "2e4f4b0000000000 0800000000000000");
					put("0x04b4f20", "2020202020206673202020202020676f312e3872633267732020202020206e6578745f67633d6e6f20616e6f64657231");
				}}),
				Arguments.of("go1.16.7", 4, new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 02 0000000000000000 0000000000000000 08 676f312e31362e37");

					put("0x0811bed0", "7f410d08 07000000");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of("go1.8.7", 4, new HashMap<String, String>(){{
					put("0x0811bec0", "53630d08 17000000 32710d08 1c000000 7f410d08 07000000");
					put("0x080d6353", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x080d7132", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x080d4170", "346673202020202067637472616365 676f312e382e37 67732020202020696e76616c696470616e69633a207265666c65");
				}}),
				Arguments.of("go1.8rc2", 8, new HashMap<String, String>(){{
					put("0x0050c620", "dc7c4b0000000000 1700000000000000 178f4b0000000000 1c00000000000000 2e4f4b0000000000 0800000000000000");
					put("0x004b7cdc", "666174616c3a206d6f7265737461636b206f6e2067300a");
					put("0x004b8f17", "666174616c3a206d6f7265737461636b206f6e20677369676e616c0a");
					put("0x004b4f20", "2020202020206673202020202020 676f312e38726332 67732020202020206e6578745f67633d6e6f20616e6f64657231");
				}}),
				Arguments.of("go0.0.0", 8, new HashMap<String, String>(){{
				}})
			);
	}

	@ParameterizedTest
	@MethodSource("test_is_go_version_params")
	public void test_is_go_version(boolean expected, String str) throws Exception {
		initialize(new HashMap<>());

		assertEquals(GolangVersion.is_go_version(str), expected);
	}

	static Stream<Arguments> test_is_go_version_params() throws Throwable {
		return Stream.of(
				Arguments.of(true, "go1"),
				Arguments.of(true, "go1.1beta1"),
				Arguments.of(true, "go1.1beta2"),
				Arguments.of(true, "go1.15rc1"),
				Arguments.of(true, "go1.15rc2"),
				Arguments.of(true, "go1.1.1beta1"),
				Arguments.of(true, "go1.16"),
				Arguments.of(true, "go1.16.7"),
				Arguments.of(false, ""),
				Arguments.of(false, "go1.16.rc1"),
				Arguments.of(false, "go1.16.7.8")
			);
	}

	@ParameterizedTest
	@MethodSource("test_extract_go_version_params")
	public void test_extract_go_version(String expected, String data) throws Exception {
		initialize(new HashMap<String, String>());

		assertEquals(GolangVersion.extract_go_version(data), Optional.ofNullable(expected));
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
	@MethodSource("test_compare_go_version_params")
	public void test_compare_go_version(int expected, String cmp1, String cmp2) throws Exception {
		initialize(new HashMap<>());

		assertEquals(GolangVersion.compare_go_version(cmp1, cmp2), expected);
	}

	static Stream<Arguments> test_compare_go_version_params() throws Throwable {
		return Stream.of(
				Arguments.of(0, "go1.16.7", "go1.16.7"),
				Arguments.of(1, "go1.16.7", "go1.16.6"),
				Arguments.of(-1, "go1.16.7", "go1.16.8"),
				Arguments.of(1, "go1.17.7", "go1.16.8"),
				Arguments.of(-1, "go1.16.7", "go1.17.6"),
				Arguments.of(1, "go2.16.7", "go1.17.6"),
				Arguments.of(-1, "go0.17.7", "go1.16.8"),
				Arguments.of(1, "go1.16.7", "go1.16"),
				Arguments.of(1, "go1.16", "go0.16rc1"),
				Arguments.of(1, "go1.16", "go0.16beta1"),
				Arguments.of(1, "go1.16.1", "go1.16rc1"),
				Arguments.of(1, "go1.16.1", "go1.16beta1"),
				Arguments.of(1, "go1.16rc1", "go1.16beta1"),
				Arguments.of(1, "go1.16rc2", "go1.16rc1"),
				Arguments.of(1, "go1.16beta2", "go1.16beta1"),
				Arguments.of(-1, "go1", "go1.1")
			);
	}
}
