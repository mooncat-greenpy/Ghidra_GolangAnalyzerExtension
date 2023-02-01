package golanganalyzerextension.datatype;

import static org.junit.Assert.assertEquals;

import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import golanganalyzerextension.datatype.UncommonType.UncommonMethod;
import golanganalyzerextension.gobinary.GolangBinary;

public class UncommonTypeTest extends AbstractGhidraHeadlessIntegrationTest {
	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		builder.createMemory(".text", "00401000", 0x1000);
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
					put("0x004a94b0", "3a110000 0000 0000 1c000000");
					put("0x0049313a", "0000077265666c656374");

					put("0x00600000", "fbffffff 00 00 01 04 00000000");
					put("0x0060000c", "00104000 00200000");
					put("0x00602000", "00104000");
				}}),
				Arguments.of("reflect", false, new HashMap<String, String>(){{
					put("0x004a94b0", "3a110000 0000 0000 1c000000");
					put("0x0049313a", "0000077265666c656374");

					put("0x00600000", "fbffffff 00 00 01 08 0000000000000000");
					put("0x00600010", "0010400000000000 0020000000000000");
					put("0x00602000", "0010400000000000");
				}}),
				Arguments.of("reflect", false, new HashMap<String, String>(){{
					put("0x004a94b0", "3a110000 0000 0000 1c000000");
					put("0x0049313a", "00077265666c656374");
					// go version 1.17
					put("0x529000", "ff20476f206275696c64696e663a 08 00 7872530000000000 9872530000000000");
					put("0x537278", "d5f64a0000000000 0600000000000000");
					put("0x4af6d5", "676f312e3137");

					put("0x00600000", "fbffffff 00 00 01 08 0000000000000000");
					put("0x00600010", "0010400000000000 0020000000000000");
					put("0x00602000", "0010400000000000");
				}}),
				Arguments.of("reflect", true, new HashMap<String, String>(){{
					put("0x004a94b0", "00000000 90725300 cc944a00 00000000 00000000");
					put("0x00537290", "3a314900 07000000");
					put("0x0049313a", "7265666c656374");

					put("0x00600000", "fbffffff 00 00 01 04 00000000");
					put("0x0060000c", "00104000 00200000");
					put("0x00602000", "00104000");
				}}),
				Arguments.of("reflect", true, new HashMap<String, String>(){{
					put("0x004a94b0", "0000000000000000 9072530000000000 cc944a0000000000 0000000000000000 0000000000000000");
					put("0x00537290", "3a31490000000000 0700000000000000");
					put("0x0049313a", "7265666c656374");

					put("0x00600000", "fbffffff 00 00 01 08 0000000000000000");
					put("0x00600010", "0010400000000000 0020000000000000");
					put("0x00602000", "0010400000000000");
				}})
			);
	}

	@ParameterizedTest
	@MethodSource("test_get_memthod_list_params")
	public void test_get_memthod_list(List<String> name_list, List<Long> type_offset_list, List<Long> func_addr_value_list, boolean is_go16, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		UncommonType go_uncommon_type=new UncommonType(go_bin, go_bin.get_address(0x004a94b0), go_bin.get_address(0x00492000), is_go16);

		List<UncommonMethod> method_list=go_uncommon_type.get_method_list();
		assertEquals(method_list.size(), name_list.size());
		for(int i=0; i<method_list.size(); i++) {
			assertEquals(method_list.get(i).get_name(), name_list.get(i));
			assertEquals((Long)method_list.get(i).get_type_offset(), type_offset_list.get(i));
			assertEquals((Long)method_list.get(i).get_interface_method_addr().orElse(go_bin.get_address(0)).getOffset(), func_addr_value_list.get(i));
			assertEquals((Long)method_list.get(i).get_normal_method_addr().orElse(go_bin.get_address(0)).getOffset(), func_addr_value_list.get(i));
		}
	}

	static Stream<Arguments> test_get_memthod_list_params() throws Throwable {
		return Stream.of(
				Arguments.of(Arrays.asList("data", "pkgPath"), Arrays.asList((long)0x0, (long)0x9d40), Arrays.asList((long)0, (long)0x0046dbc0), false, new HashMap<String, String>(){{
					put("0x004a94b0", "3a110000 0200 0000 1c000000");
					put("0x004a94cc", "20050000ffffffffffffffffffffffff 5e150000409d0000c0cb0600c0cb0600");
					put("0x00492520", "00000464617461");
					put("0x0049355e", "000007706b6750617468");
					put("0x0049313a", "0000077265666c656374");

					put("0x00600000", "fbffffff 00 00 01 04 00000000");
					put("0x0060000c", "00104000 00200000");
					put("0x00602000", "00104000");
				}}),
				Arguments.of(Arrays.asList("data", "pkgPath"), Arrays.asList((long)0x9d40, (long)0x86d0), Arrays.asList((long)0, (long)0x0046dbc0), true, new HashMap<String, String>(){{
					put("0x004a94b0", "0000000000000000 9072530000000000 e0944a0000000000 0200000000000000 0200000000000000");
					put("0x004a94e0", "2074530000000000 7074530000000000 40bd490000000000 40bd490000000000 0000000000000000 0000000000000000 3074530000000000 b074530000000000 d0a6490000000000 d0a6490000000000 c0db460000000000 c0db460000000000");
					put("0x00537420", "5031490000000000 0400000000000000");
					put("0x00493150", "64617461");
					put("0x00537430", "2011490000000000 0700000000000000");
					put("0x00491120", "706b6750617468");
					put("0x00537290", "3a31490000000000 0700000000000000");
					put("0x0049313a", "7265666c656374");

					put("0x00600000", "fbffffff 00 00 01 08 0000000000000000");
					put("0x00600010", "0010400000000000 0020000000000000");
					put("0x00602000", "0010400000000000");
				}})
			);
	}
}
