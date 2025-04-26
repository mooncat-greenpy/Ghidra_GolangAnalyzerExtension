package golanganalyzerextension.gobinary;

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

import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.PcHeader.GO_VERSION;

public class FuncInfoTest {
	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_func_info_params")
	public void test_func_info(long expected_func_addr, long expected_info_addr, int expected_name_offset, int expected_arg_size, int expected_pcsp_offset, int expected_pcfile_offset, int expected_pcln_offset, int expected_cu_offset, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);

		try {
			GolangBinary go_bin=new GolangBinary(program, "", TaskMonitor.DUMMY);
			PcHeader pcheader=new PcHeader(go_bin);

			FuncInfo info=new FuncInfo(go_bin, go_bin.get_address(0x600000), go_bin.get_address(0x600010), false);

			assertEquals(info.get_info_tab().get_func_addr().getOffset(), expected_func_addr);
			assertEquals(info.get_info_tab().get_info_addr().getOffset(), expected_info_addr);
			assertEquals(info.get_func_addr().getOffset(), expected_func_addr);
			assertEquals(info.get_name_offset(), expected_name_offset);
			assertEquals(info.get_arg_size(), expected_arg_size);
			assertEquals(info.get_pcsp_offset(), expected_pcsp_offset);
			assertEquals(info.get_pcfile_offset(), expected_pcfile_offset);
			assertEquals(info.get_pcln_offset(), expected_pcln_offset);
			assertEquals(info.get_cu_offset(), expected_cu_offset);
		} catch(InvalidBinaryStructureException e) {
			assertEquals(true, false);
		}
	}

	static Stream<Arguments> test_func_info_params() throws Throwable {
		return Stream.of(
				Arguments.of((long) 0x401080, (long) 0x601000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x7000, new HashMap<String, String>(){{
					// 1, 4, GO_VERSION.GO_12
					put("0x500000", "fbffffff 00 00 01 04 00000000");
					put("0x50000c", "00104000 00200000");
					put("0x502000", "00104000");

					put("0x600000", "00000000 00000000");
					put("0x600010", "80104000 00101000 c0104000 00201000");
					put("0x601000", "80104000 00200000 08000000 00000000 00300000 00400000 00500000 00000000 00700000");

					put("0x401080", "00000000");
				}}),
				Arguments.of((long) 0x401080, (long) 0x601000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x7000, new HashMap<String, String>(){{
					// 2, 8, GO_VERSION.GO_12
					put("0x500000", "fbffffff 00 00 02 08 0000000000000000");
					put("0x500010", "0010400000000000 0020000000000000");
					put("0x502000", "0010400000000000");

					put("0x600000", "0000000000000000 0000000000000000");
					put("0x600010", "8010400000000000 0010100000000000 c010400000000000 0020100000000000");
					put("0x601000", "8010400000000000 00200000 08000000 00000000 00300000 00400000 00500000 00000000 00700000");

					put("0x401080", "00000000");
				}}),
				Arguments.of((long) 0x401080, (long) 0x601000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x7000, new HashMap<String, String>(){{
					// 4, 4, GO_VERSION.GO_116
					put("0x500000", "faffffff 00 00 04 04 00000000 00000000 00000000 00000000 00000000 00000000 00100000");
					put("0x501000", "00104000 00100000");
					put("0x502000", "00104000");

					put("0x600000", "00000000 00000000");
					put("0x600010", "80104000 00100000 c0104000 00200000");
					put("0x601000", "80104000 00200000 08000000 00000000 00300000 00400000 00500000 00000000 00700000");

					put("0x401080", "00000000");
				}}),
				Arguments.of((long) 0x401080, (long) 0x601000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x7000, new HashMap<String, String>(){{
					// 1, 8, GO_VERSION.GO_116
					put("0x500000", "faffffff 00 00 01 08 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0010000000000000");
					put("0x501000", "0010400000000000 0010000000000000");
					put("0x502000", "0010400000000000");

					put("0x600000", "0000000000000000 0000000000000000");
					put("0x600010", "8010400000000000 0010000000000000 c010400000000000 0020000000000000");
					put("0x601000", "8010400000000000 00200000 08000000 00000000 00300000 00400000 00500000 00000000 00700000");

					put("0x401080", "00000000");
				}}),
				Arguments.of((long) 0x401080, (long) 0x601000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x7000, new HashMap<String, String>(){{
					// 2, 4, GO_VERSION.GO_118
					put("0x500000", "f0ffffff 00 00 02 04 00000000 00000000 00104000 00000000 00000000 00000000 00000000 00100000");
					put("0x501000", "02000000 00100000");
					put("0x502000", "02000000");

					put("0x600000", "00000000 00000000");
					put("0x600010", "80000000 00100000 c0000000 00200000");
					put("0x601000", "80000000 00200000 08000000 00000000 00300000 00400000 00500000 00000000 00700000");

					put("0x401080", "00000000");
				}}),
				Arguments.of((long) 0x401080, (long) 0x601000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x7000, new HashMap<String, String>(){{
					// 2, 8, GO_VERSION.GO_118
					put("0x500000", "f0ffffff 00 00 04 08 0000000000000000 0000000000000000 0010400000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0010000000000000");
					put("0x501000", "02000000 00100000");
					put("0x502000", "02000000");

					put("0x600000", "00000000 00000000");
					put("0x600010", "80000000 00100000 c0000000 00200000");
					put("0x601000", "80000000 00200000 08000000 00000000 00300000 00400000 00500000 00000000 00700000");

					put("0x401080", "00000000");
				}}),
				Arguments.of((long) 0x401080, (long) 0x601000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x7000, new HashMap<String, String>(){{
					// 2, 4, GO_VERSION.GO_120
					put("0x500000", "f1ffffff 00 00 02 04 00000000 00000000 00104000 00000000 00000000 00000000 00000000 00100000");
					put("0x501000", "02000000 00100000");
					put("0x502000", "02000000");

					put("0x600000", "00000000 00000000");
					put("0x600010", "80000000 00100000 c0000000 00200000");
					put("0x601000", "80000000 00200000 08000000 00000000 00300000 00400000 00500000 00000000 00700000");

					put("0x401080", "00000000");
				}}),
				Arguments.of((long) 0x401080, (long) 0x601000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x7000, new HashMap<String, String>(){{
					// 4, 8, GO_VERSION.GO_120
					put("0x500000", "f1ffffff 00 00 04 08 0000000000000000 0000000000000000 0010400000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0010000000000000");
					put("0x501000", "02000000 00100000");
					put("0x502000", "02000000");

					put("0x600000", "00000000 00000000");
					put("0x600010", "80000000 00100000 c0000000 00200000");
					put("0x601000", "80000000 00200000 08000000 00000000 00300000 00400000 00500000 00000000 00700000");

					put("0x401080", "00000000");
				}})
			);
	}

	@ParameterizedTest
	@MethodSource("test_func_info_force_params")
	public void test_func_info_force(long expected_func_addr, long expected_info_addr, int expected_name_offset, int expected_arg_size, int expected_pcsp_offset, int expected_pcfile_offset, int expected_pcln_offset, int expected_cu_offset, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);

		try {
			GolangBinary go_bin=new GolangBinary(program, "", TaskMonitor.DUMMY);
			PcHeader pcheader=new PcHeader(go_bin);

			FuncInfo info=new FuncInfo(go_bin, go_bin.get_address(0x600000), go_bin.get_address(0x600010), true);

			assertEquals(info.get_info_tab().get_func_addr().getOffset(), expected_func_addr);
			assertEquals(info.get_info_tab().get_info_addr().getOffset(), expected_info_addr);
			assertEquals(info.get_func_addr().getOffset(), expected_func_addr);
			assertEquals(info.get_name_offset(), expected_name_offset);
			assertEquals(info.get_arg_size(), expected_arg_size);
			assertEquals(info.get_pcsp_offset(), expected_pcsp_offset);
			assertEquals(info.get_pcfile_offset(), expected_pcfile_offset);
			assertEquals(info.get_pcln_offset(), expected_pcln_offset);
			assertEquals(info.get_cu_offset(), expected_cu_offset);
		} catch(InvalidBinaryStructureException e) {
			System.out.println(e);
			assertEquals(true, false);
		}
	}

	static Stream<Arguments> test_func_info_force_params() throws Throwable {
		return Stream.of(
				Arguments.of((long) 0x401080, (long) 0x601000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x7000, new HashMap<String, String>(){{
					// 1, 4, GO_VERSION.GO_12
					put("0x500000", "fbffffff 00 00 01 04 00000000");
					put("0x50000c", "00104000 00200000");
					put("0x502000", "00104000");

					put("0x600000", "00000000 00000000");
					put("0x600010", "80104000 00101000 c0104000 00201000");
					put("0x601000", "80104000 00200000 08000000 00000000 00300000 00400000 00500000 00000000 00700000");

					put("0x401080", "00000000");
				}}),
				Arguments.of((long) 0x401080, (long) 0x601000, 0x2000, 8, 0x3000, 0x4000, 0x5000, 0x7000, new HashMap<String, String>(){{
					// 1, 4, GO_VERSION.GO_12
					put("0x500000", "fbffffff 00 00 01 04 00000000");
					put("0x50000c", "00104000 00200000");
					put("0x502000", "00104000");

					put("0x600000", "00000000 00000000");
					put("0x600010", "80104000 00101000 c0104000 00201000");
					put("0x601000", "ffffffff 00200000 08000000 00000000 00300000 00400000 00500000 00000000 00700000");

					put("0x401080", "00000000");
				}})
		);
	}
}
