package golanganalyzerextension.version;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

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
	@MethodSource("test_eq_params")
	public void test_eq(boolean expected, String cmp1, String cmp2) throws Exception {
		initialize(new HashMap<>());

		GolangVersion go_version=new GolangVersion(cmp1);
		assertEquals(go_version.eq(cmp2), expected);
	}

	static Stream<Arguments> test_eq_params() throws Throwable {
		return Stream.of(
				Arguments.of(true, "go1.16.7", "go1.16.7"),
				Arguments.of(true, "go1.16.7rc1", "go1.16.7rc1"),
				Arguments.of(true, "go1.16beta1", "go1.16beta1"),
				Arguments.of(false, "go1.16.7", "go1.16.6"),
				Arguments.of(false, "go1.16.7", "go1.16.8"),
				Arguments.of(false, "go1.17.7", "go1.16.8"),
				Arguments.of(false, "go1.16.7", "go1.17.6"),
				Arguments.of(false, "go2.16.7", "go1.17.6"),
				Arguments.of(false, "go0.17.7", "go1.16.8"),
				Arguments.of(false, "go1.16.7", "go1.16"),
				Arguments.of(false, "go1.16", "go0.16rc1"),
				Arguments.of(false, "go1.16", "go0.16beta1"),
				Arguments.of(false, "go1.16.1", "go1.16rc1"),
				Arguments.of(false, "go1.16.1", "go1.16beta1"),
				Arguments.of(false, "go1.16rc1", "go1.16beta1"),
				Arguments.of(false, "go1.16rc2", "go1.16rc1"),
				Arguments.of(false, "go1.16beta2", "go1.16beta1"),
				Arguments.of(false, "go1", "go1.1")
			);
	}

	@ParameterizedTest
	@MethodSource("test_gt_params")
	public void test_gt(boolean expected, String cmp1, String cmp2) throws Exception {
		initialize(new HashMap<>());

		GolangVersion go_version=new GolangVersion(cmp1);
		assertEquals(go_version.gt(cmp2), expected);
	}

	static Stream<Arguments> test_gt_params() throws Throwable {
		return Stream.of(
				Arguments.of(false, "go1.16.7", "go1.16.7"),
				Arguments.of(true, "go1.16.7", "go1.16.6"),
				Arguments.of(false, "go1.16.7", "go1.16.8"),
				Arguments.of(true, "go1.17.7", "go1.16.8"),
				Arguments.of(false, "go1.16.7", "go1.17.6"),
				Arguments.of(true, "go2.16.7", "go1.17.6"),
				Arguments.of(false, "go0.17.7", "go1.16.8"),
				Arguments.of(true, "go1.16.7", "go1.16"),
				Arguments.of(true, "go1.16", "go0.16rc1"),
				Arguments.of(true, "go1.16", "go0.16beta1"),
				Arguments.of(true, "go1.16.1", "go1.16rc1"),
				Arguments.of(true, "go1.16.1", "go1.16beta1"),
				Arguments.of(true, "go1.16rc1", "go1.16beta1"),
				Arguments.of(true, "go1.16rc2", "go1.16rc1"),
				Arguments.of(true, "go1.16beta2", "go1.16beta1"),
				Arguments.of(false, "go1", "go1.1")
			);
	}

	@ParameterizedTest
	@MethodSource("test_lt_params")
	public void test_lt(boolean expected, String cmp1, String cmp2) throws Exception {
		initialize(new HashMap<>());

		GolangVersion go_version=new GolangVersion(cmp1);
		assertEquals(go_version.lt(cmp2), expected);
	}

	static Stream<Arguments> test_lt_params() throws Throwable {
		return Stream.of(
				Arguments.of(false, "go1.16.7", "go1.16.7"),
				Arguments.of(false, "go1.16.7", "go1.16.6"),
				Arguments.of(true, "go1.16.7", "go1.16.8"),
				Arguments.of(false, "go1.17.7", "go1.16.8"),
				Arguments.of(true, "go1.16.7", "go1.17.6"),
				Arguments.of(false, "go2.16.7", "go1.17.6"),
				Arguments.of(true, "go0.17.7", "go1.16.8"),
				Arguments.of(false, "go1.16.7", "go1.16"),
				Arguments.of(false, "go1.16", "go0.16rc1"),
				Arguments.of(false, "go1.16", "go0.16beta1"),
				Arguments.of(false, "go1.16.1", "go1.16rc1"),
				Arguments.of(false, "go1.16.1", "go1.16beta1"),
				Arguments.of(false, "go1.16rc1", "go1.16beta1"),
				Arguments.of(false, "go1.16rc2", "go1.16rc1"),
				Arguments.of(false, "go1.16beta2", "go1.16beta1"),
				Arguments.of(true, "go1", "go1.1")
			);
	}

	@ParameterizedTest
	@MethodSource("test_ge_params")
	public void test_ge(boolean expected, String cmp1, String cmp2) throws Exception {
		initialize(new HashMap<>());

		GolangVersion go_version=new GolangVersion(cmp1);
		assertEquals(go_version.ge(cmp2), expected);
	}

	static Stream<Arguments> test_ge_params() throws Throwable {
		return Stream.of(
				Arguments.of(true, "go1.16.7", "go1.16.7"),
				Arguments.of(true, "go1.16.7", "go1.16.6"),
				Arguments.of(false, "go1.16.7", "go1.16.8"),
				Arguments.of(true, "go1.17.7", "go1.16.8"),
				Arguments.of(false, "go1.16.7", "go1.17.6"),
				Arguments.of(true, "go2.16.7", "go1.17.6"),
				Arguments.of(false, "go0.17.7", "go1.16.8"),
				Arguments.of(true, "go1.16.7", "go1.16"),
				Arguments.of(true, "go1.16", "go0.16rc1"),
				Arguments.of(true, "go1.16", "go0.16beta1"),
				Arguments.of(true, "go1.16.1", "go1.16rc1"),
				Arguments.of(true, "go1.16.1", "go1.16beta1"),
				Arguments.of(true, "go1.16rc1", "go1.16beta1"),
				Arguments.of(true, "go1.16rc2", "go1.16rc1"),
				Arguments.of(true, "go1.16beta2", "go1.16beta1"),
				Arguments.of(false, "go1", "go1.1")
			);
	}

	@ParameterizedTest
	@MethodSource("test_le_params")
	public void test_le(boolean expected, String cmp1, String cmp2) throws Exception {
		initialize(new HashMap<>());

		GolangVersion go_version=new GolangVersion(cmp1);
		assertEquals(go_version.le(cmp2), expected);
	}

	static Stream<Arguments> test_le_params() throws Throwable {
		return Stream.of(
				Arguments.of(true, "go1.16.7", "go1.16.7"),
				Arguments.of(false, "go1.16.7", "go1.16.6"),
				Arguments.of(true, "go1.16.7", "go1.16.8"),
				Arguments.of(false, "go1.17.7", "go1.16.8"),
				Arguments.of(true, "go1.16.7", "go1.17.6"),
				Arguments.of(false, "go2.16.7", "go1.17.6"),
				Arguments.of(true, "go0.17.7", "go1.16.8"),
				Arguments.of(false, "go1.16.7", "go1.16"),
				Arguments.of(false, "go1.16", "go0.16rc1"),
				Arguments.of(false, "go1.16", "go0.16beta1"),
				Arguments.of(false, "go1.16.1", "go1.16rc1"),
				Arguments.of(false, "go1.16.1", "go1.16beta1"),
				Arguments.of(false, "go1.16rc1", "go1.16beta1"),
				Arguments.of(false, "go1.16rc2", "go1.16rc1"),
				Arguments.of(false, "go1.16beta2", "go1.16beta1"),
				Arguments.of(true, "go1", "go1.1")
			);
	}
}
