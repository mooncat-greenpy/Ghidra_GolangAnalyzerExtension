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
import ghidra.util.task.TaskMonitor;
import golanganalyzerextension.GolangBinary;
import golanganalyzerextension.UncommonType;

public class UncommonTypeTest extends AbstractGhidraHeadlessIntegrationTest {
	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_get_pkg_path_params")
	public void test_get_pkg_path(String expected, boolean is_go16, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		UncommonType go_uncommon_type=new UncommonType(go_bin, go_bin.get_address(0x004a94b0), go_bin.get_address(0x00492000), is_go16);

		assertEquals(go_uncommon_type.get_pkg_path(), expected);
	}

	static Stream<Arguments> test_get_pkg_path_params() throws Throwable {
		return Stream.of(
				Arguments.of("reflect", false, new HashMap<String, String>(){{
					put("0x004a94b0", "3a110000 0700 0000 1c000000 00000000f8294900a0a3490000000000");
					put("0x0049313a", "0000077265666c656374");
				}}),
				Arguments.of("reflect", false, new HashMap<String, String>(){{
					put("0x004a94b0", "3a110000 0700 0000 1c000000 00000000f8294900a0a3490000000000");
					put("0x0049313a", "00077265666c656374");
					// go version 1.17
					put("0x529000", "ff20476f206275696c64696e663a 08 00 7872530000000000 9872530000000000");
					put("0x537278", "d5f64a0000000000 0600000000000000");
					put("0x4af6d5", "676f312e3137");

				}})
			);
	}

}
