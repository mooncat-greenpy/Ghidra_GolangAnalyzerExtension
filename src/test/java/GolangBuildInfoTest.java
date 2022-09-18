import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import golanganalyzerextension.GolangBinary;
import golanganalyzerextension.GolangBuildInfo;

public class GolangBuildInfoTest extends AbstractGhidraHeadlessIntegrationTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_get_build_info_addr_params")
	public void test_get_build_info_addr(boolean expected, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		GolangBuildInfo go_build_info=new GolangBuildInfo(go_bin);

		Method method=GolangBuildInfo.class.getDeclaredMethod("get_build_info_addr");
		method.setAccessible(true);
		@SuppressWarnings("unchecked")
		Optional<Address> addr_opt=(Optional<Address>)method.invoke(go_build_info);
		assertEquals(addr_opt.isPresent(), expected);

		addr_opt.ifPresent(addr -> {assert addr_opt.get().equals(go_bin.get_address(0x529000));});
	}

	static Stream<Arguments> test_get_build_info_addr_params() throws Throwable {
		return Stream.of(
				Arguments.of(true, new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 00 78725300 98725300 0000000000000000");
				}}),
				Arguments.of(false, new HashMap<String, String>(){{
					put("0x529000", "0020476f206275696c64696e663a 04 00 78725300 98725300 0000000000000000");
				}})
			);
	}

	@ParameterizedTest
	@MethodSource("test_find_go_version_params")
	public void test_find_go_version(String expected, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		GolangBuildInfo go_build_info=new GolangBuildInfo(go_bin);

		Optional<String> str_opt=go_build_info.find_go_version(go_bin.get_address("0x529000"));
		assertTrue(str_opt.isPresent());

		str_opt.ifPresent(str -> assertEquals(str, expected));
	}

	static Stream<Arguments> test_find_go_version_params() throws Throwable {
		return Stream.of(
				Arguments.of("go1.16.7", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 00 78725300 98725300 0000000000000000");
					put("0x537278", "d5f64a00 08000000");
					put("0x4af6d5", "676f312e31362e37");
				}}),
				Arguments.of("go1.16.5", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 00 78725300 98725300 0000000000000000");
					put("0x537278", "d5f64a00 08000000");
					put("0x4af6d5", "676f312e31362e35");
				}}),
				Arguments.of("go1.16", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 00 78725300 98725300 0000000000000000");
					put("0x537278", "d5f64a00 06000000");
					put("0x4af6d5", "676f312e31362e37");
				}}),
				Arguments.of("go1.16.7", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 08 00 7872530000000000 9872530000000000");
					put("0x537278", "d5f64a0000000000 0800000000000000");
					put("0x4af6d5", "676f312e31362e37");
				}}),
				Arguments.of("go1.16", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 08 00 7872530000000000 9872530000000000");
					put("0x537278", "d5f64a0000000000 0600000000000000");
					put("0x4af6d5", "676f312e31362e37");
				}}),

				Arguments.of("go1.16.7", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 02 0000000000000000 0000000000000000 08 676f312e31362e37");
				}}),
				Arguments.of("go1.16.7", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 08 02 0000000000000000 0000000000000000 08 676f312e31362e37");
				}})
			);
	}

	@ParameterizedTest
	@MethodSource("test_find_module_version_params")
	public void test_find_module_version(String expected, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		GolangBuildInfo go_build_info=new GolangBuildInfo(go_bin);

		Optional<String> str_opt=go_build_info.find_module_version(go_bin.get_address("0x529000"));
		assertTrue(str_opt.isPresent());

		str_opt.ifPresent(str -> assertEquals(str, expected));
	}

	static Stream<Arguments> test_find_module_version_params() throws Throwable {
		return Stream.of(
				Arguments.of("pathcommand-line-argumentsmodcommand-line-arguments(devel)", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 00 78725300 98725300 0000000000000000");
					put("0x00537298", "bb834b00 60000000");
					put("0x004b83bb", "3077af0c9274080241e1c107e6d618e6 7061746809636f6d6d616e642d6c696e652d617267756d656e74730a6d6f6409636f6d6d616e642d6c696e652d617267756d656e74730928646576656c29090a f932433186182072008242104116d8f2");
				}}),
				Arguments.of("pathcommand-line-argumentsmodcommand-line-arguments(devel)", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 08 00 7872530000000000 9872530000000000");
					put("0x00537298", "bb834b0000000000 6000000000000000");
					put("0x004b83bb", "3077af0c9274080241e1c107e6d618e6 7061746809636f6d6d616e642d6c696e652d617267756d656e74730a6d6f6409636f6d6d616e642d6c696e652d617267756d656e74730928646576656c29090a f932433186182072008242104116d8f2");
				}})
			);
	}

	@ParameterizedTest
	@MethodSource("test_is_go_version_params")
	public void test_is_go_version(boolean expected, String go_version) throws Exception {
		initialize(new HashMap<>());
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		GolangBuildInfo go_build_info=new GolangBuildInfo(go_bin);

		assertEquals(go_build_info.is_go_version(go_version), expected);
	}

	static Stream<Arguments> test_is_go_version_params() throws Throwable {
		return Stream.of(
				Arguments.of(true, "go1"),
				Arguments.of(true, "go1.1beta1"),
				Arguments.of(true, "go1.1beta2"),
				Arguments.of(true, "go1.15rc1"),
				Arguments.of(true, "go1.15rc2"),
				Arguments.of(true, "go1.16"),
				Arguments.of(true, "go1.16.7"),
				Arguments.of(false, ""),
				Arguments.of(false, "go1beta1"),
				Arguments.of(false, "go1.16.rc1"),
				Arguments.of(false, "go1.16.7.8")
			);
	}

	@ParameterizedTest
	@MethodSource("test_compare_go_version_params")
	public void test_compare_go_version(int expected, String cmp1, String cmp2) throws Exception {
		initialize(new HashMap<>());
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		GolangBuildInfo go_build_info=new GolangBuildInfo(go_bin);

		assertEquals(go_build_info.compare_go_version(cmp1, cmp2), expected);
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

	@ParameterizedTest
	@MethodSource("test_golang_build_info_params")
	public void test_golang_build_info(String expected_go_version, String expected_module_version, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		GolangBuildInfo go_build_info=new GolangBuildInfo(go_bin);

		assertEquals(go_build_info.get_go_version(), expected_go_version);
		assertEquals(go_build_info.get_module_version(), expected_module_version);
	}

	static Stream<Arguments> test_golang_build_info_params() throws Throwable {
		return Stream.of(
				Arguments.of("go1.16.7", "pathcommand-line-argumentsmodcommand-line-arguments(devel)", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 00 78725300 98725300 0000000000000000");
					put("0x537278", "d5f64a00 08000000");
					put("0x4af6d5", "676f312e31362e37");
					put("0x00537298", "bb834b00 60000000");
					put("0x004b83bb", "3077af0c9274080241e1c107e6d618e6 7061746809636f6d6d616e642d6c696e652d617267756d656e74730a6d6f6409636f6d6d616e642d6c696e652d617267756d656e74730928646576656c29090a f932433186182072008242104116d8f2");
				}}),
				Arguments.of("go1.16.7", "pathcommand-line-argumentsmodcommand-line-arguments(devel)", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 08 00 7872530000000000 9872530000000000");
					put("0x537278", "d5f64a0000000000 0800000000000000");
					put("0x4af6d5", "676f312e31362e37");
					put("0x00537298", "bb834b0000000000 6000000000000000");
					put("0x004b83bb", "3077af0c9274080241e1c107e6d618e6 7061746809636f6d6d616e642d6c696e652d617267756d656e74730a6d6f6409636f6d6d616e642d6c696e652d617267756d656e74730928646576656c29090a f932433186182072008242104116d8f2");
				}}),
				Arguments.of("go1.16.7", "", new HashMap<String, String>(){{
					put("0x529000", "ff20476f206275696c64696e663a 04 02 0000000000000000 0000000000000000 08 676f312e31362e37");
				}})
			);
	}
}
