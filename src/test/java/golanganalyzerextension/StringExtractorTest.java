package golanganalyzerextension;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

public class StringExtractorTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_string_extractor_params")
	public void test_string_extractor(Map<Long, String> expected, int pointer_size, Map<String, String> bytes_map) throws Exception {
		initialize(bytes_map);
		GolangBinary go_bin=new GolangBinary(new GolangBinary(program, TaskMonitor.DUMMY), null, null, null, null, null, 0, 0, pointer_size, null);
		GolangAnalyzerExtensionService service=new GolangAnalyzerExtensionDummyService();

		StringExtractor string_extractor=new StringExtractor(go_bin, service);

		assertEquals(string_extractor.get_string_map(), expected);
		assertEquals(service.get_string_map(), expected);
	}

	static Stream<Arguments> test_string_extractor_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05001000, "name");
						}},
						4,
						new HashMap<String, String>(){{
							put("0x05001000", "00200005 04000000");
							put("0x05002000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05001000, "name");
							put((long)0x05001008, "test");
						}},
						4,
						new HashMap<String, String>(){{
							put("0x05001000", "00200005 04000000 00300005 04000000");
							put("0x05002000", "6e616d656e616d65");
							put("0x05003000", "7465737474657374");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05001000, "name");
							put((long)0x0500100c, "test");
						}},
						4,
						new HashMap<String, String>(){{
							put("0x05001000", "00200005 04000000 00200005 00300005 04000000");
							put("0x05002000", "6e616d656e616d65");
							put("0x05003000", "7465737474657374");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05001000, "name");
						}},
						8,
						new HashMap<String, String>(){{
							put("0x05001000", "0020000500000000 0400000000000000");
							put("0x05002000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
						}},
						4,
						new HashMap<String, String>(){{
							put("0x05001000", "00200005 04000000");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
						}},
						4,
						new HashMap<String, String>(){{
							put("0x05001000", "00200005 000000ff");
							put("0x05002000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
						}},
						4,
						new HashMap<String, String>(){{
							put("0x05001000", "00200005 00001000");
							put("0x05002000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
						}},
						4,
						new HashMap<String, String>(){{
							put("0x05001000", "00200005 04000000 04000000");
							put("0x05002000", "6e616d656e616d65");
						}}
				)
			);
	}
}
