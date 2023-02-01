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

public class PcHeaderTest extends AbstractGhidraHeadlessIntegrationTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_get_address_params")
	public void test_get_address(boolean expected, long expected_addr_value, int expected_quantum, int expected_pointer_size, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);

		boolean result=true;
		try {
			GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);
			PcHeader pcheader=new PcHeader(go_bin);

			assertEquals(pcheader.get_addr().getOffset(), expected_addr_value);
			assertEquals(pcheader.get_quantum(), expected_quantum);
			assertEquals(pcheader.get_pointer_size(), expected_pointer_size);
		} catch(InvalidBinaryStructureException e) {
			result=false;
		}
		assertEquals(result, expected);
	}

	static Stream<Arguments> test_get_address_params() throws Throwable {
		return Stream.of(
				Arguments.of(true, 0x500000, 1, 4, new HashMap<String, String>(){{
					put("0x500000", "fbffffff 00 00 01 04 00000000");
					put("0x50000c", "00104000 00200000");
					put("0x502000", "00104000");
				}}),
				Arguments.of(false, 0x500000, 1, 4, new HashMap<String, String>(){{
					put("0x500000", "fbffffff 00 00 01 04 00000000");
					put("0x50000c", "00000000 00200000");
					put("0x502000", "00000000");
				}}),
				Arguments.of(true, 0x500000, 2, 8, new HashMap<String, String>(){{
					put("0x500000", "fbffffff 00 00 02 08 0000000000000000");
					put("0x500010", "0010400000000000 0020000000000000");
					put("0x502000", "0010400000000000");
				}}),
				Arguments.of(false, 0x500000, 2, 8, new HashMap<String, String>(){{
					put("0x500000", "fbffffff 00 00 02 08 0000000000000000");
					put("0x500010", "0000000000000000 0020000000000000");
					put("0x502000", "0000000000000000");
				}}),
				Arguments.of(true, 0x500000, 4, 4, new HashMap<String, String>(){{
					put("0x500000", "faffffff 00 00 04 04 00000000 00000000 00000000 00000000 00000000 00000000 00100000");
					put("0x501000", "00104000 00100000");
					put("0x502000", "00104000");
				}}),
				Arguments.of(false, 0x500000, 4, 4, new HashMap<String, String>(){{
					put("0x500000", "faffffff 00 00 04 04 00000000 00000000 00000000 00000000 00000000 00000000 00100000");
					put("0x501000", "00000000 00100000");
					put("0x502000", "00000000");
				}}),
				Arguments.of(true, 0x500000, 1, 8, new HashMap<String, String>(){{
					put("0x500000", "faffffff 00 00 01 08 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0010000000000000");
					put("0x501000", "0010400000000000 0010000000000000");
					put("0x502000", "0010400000000000");
				}}),
				Arguments.of(false, 0x500000, 1, 8, new HashMap<String, String>(){{
					put("0x500000", "faffffff 00 00 01 08 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0010000000000000");
					put("0x501000", "0000000000000000 0010000000000000");
					put("0x502000", "0000000000000000");
				}}),
				Arguments.of(true, 0x500000, 2, 4, new HashMap<String, String>(){{
					put("0x500000", "f0ffffff 00 00 02 04 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00100000");
					put("0x501000", "02000000 00100000");
					put("0x502000", "02000000");
				}}),
				Arguments.of(true, 0x500000, 2, 4, new HashMap<String, String>(){{
					put("0x500000", "f0ffffff 00 00 02 04 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00100000");
					put("0x501000", "00000000 00100000");
					put("0x502000", "00000000");
				}}),
				Arguments.of(false, 0x500000, 3, 4, new HashMap<String, String>(){{
					put("0x500000", "f0ffffff 00 00 03 04 00000000 00000000 00000000 00000000 00000000 00000000 00000000 00100000");
					put("0x501000", "02000000 00100000");
					put("0x502000", "02000000");
				}}),
				Arguments.of(true, 0x500000, 4, 8, new HashMap<String, String>(){{
					put("0x500000", "f0ffffff 00 00 04 08 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0010000000000000");
					put("0x501000", "02000000 00100000");
					put("0x502000", "02000000");
				}}),
				Arguments.of(true, 0x500000, 4, 8, new HashMap<String, String>(){{
					put("0x500000", "f0ffffff 00 00 04 08 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0010000000000000");
					put("0x501000", "00000000 00100000");
					put("0x502000", "00000000");
				}}),
				Arguments.of(false, 0x500000, 5, 8, new HashMap<String, String>(){{
					put("0x500000", "f0ffffff 00 00 05 08 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0000000000000000 0010000000000000");
					put("0x501000", "00000000 00100000");
					put("0x502000", "00000000");
				}})
			);
	}
}
