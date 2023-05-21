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

public class DataTypeTest  extends AbstractGhidraHeadlessIntegrationTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_get_numeric_datatype_params")
	public void test_get_numeric_datatype(int size, int expected_size) throws Exception {
		initialize(new HashMap<String, String>(){{
			put("0x500000", "fbffffff 00 00 01 04 00000000");
			put("0x50000c", "00104000 00200000");
			put("0x502000", "00104000");
		}});

		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);

		assertEquals(go_bin.get_signed_numeric_datatype(size).getLength(), expected_size);
		assertEquals(go_bin.get_unsigned_numeric_datatype(size).getLength(), expected_size);
	}

	static Stream<Arguments> test_get_numeric_datatype_params() throws Throwable {
		return Stream.of(
				Arguments.of(1, 1),
				Arguments.of(2, 2),
				Arguments.of(3, 3),
				Arguments.of(4, 4),
				Arguments.of(5, 5),
				Arguments.of(6, 6),
				Arguments.of(7, 7),
				Arguments.of(8, 8),
				Arguments.of(16, 16)
			);
	}

	@ParameterizedTest
	@MethodSource("test_get_numeric_datatype_exception_params")
	public void test_get_numeric_datatype_exception(int size, boolean expected) throws Exception {
		initialize(new HashMap<String, String>(){{
			put("0x500000", "fbffffff 00 00 01 04 00000000");
			put("0x50000c", "00104000 00200000");
			put("0x502000", "00104000");
		}});

		GolangBinary go_bin=new GolangBinary(program, TaskMonitor.DUMMY);
		boolean signed_result=true;
		try {
			go_bin.get_signed_numeric_datatype(size);
		} catch(InvalidBinaryStructureException e) {
			signed_result=false;
		}
		assertEquals(signed_result, expected);

		boolean unsigned_result=true;
		try {
			go_bin.get_unsigned_numeric_datatype(size);
		} catch(InvalidBinaryStructureException e) {
			unsigned_result=false;
		}
		assertEquals(unsigned_result, expected);
	}

	static Stream<Arguments> test_get_numeric_datatype_exception_params() throws Throwable {
		return Stream.of(
				Arguments.of(1, true),
				Arguments.of(2, true),
				Arguments.of(3, true),
				Arguments.of(4, true),
				Arguments.of(5, true),
				Arguments.of(6, true),
				Arguments.of(7, true),
				Arguments.of(8, true),
				Arguments.of(9, false),
				Arguments.of(10, false),
				Arguments.of(11, false),
				Arguments.of(12, false),
				Arguments.of(13, false),
				Arguments.of(14, false),
				Arguments.of(15, false),
				Arguments.of(16, true),
				Arguments.of(17, false)
			);
	}
}
