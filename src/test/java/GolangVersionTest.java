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
	@MethodSource("test_compare_go_version_params")
	public void test_compare_go_version(int expected, String cmp1, String cmp2) throws Exception {
		initialize(new HashMap<>());

		GolangVersion go_version=new GolangVersion(cmp1);
		assertEquals(go_version.eq(cmp2), expected);
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
