package golanganalyzerextension;

import static org.junit.Assert.assertEquals;

import java.lang.reflect.Method;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
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

	protected void initialize_with_func(String lang_name, Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", lang_name, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.disassemble(entry.getKey(), entry.getValue().length()/2);
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

	@ParameterizedTest
	@MethodSource("test_search_inst_params")
	public void test_search_inst(Map<Long, String> expected, String lang_name, int pointer_size, Map<String, String> bytes_map) throws Exception {
		initialize_with_func(lang_name, bytes_map);
		GolangBinary go_bin=new GolangBinary(new GolangBinary(program, TaskMonitor.DUMMY), null, null, null, null, null, 0, 0, pointer_size, null);
		GolangAnalyzerExtensionService service=new GolangAnalyzerExtensionDummyService();

		StringExtractor string_extractor=new StringExtractor(go_bin, service);

		Method method=StringExtractor.class.getDeclaredMethod("search_function", Address.class, int.class);
		method.setAccessible(true);

		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			method.invoke(string_extractor, go_bin.get_address(Integer.decode(entry.getKey())), entry.getValue().length()/2);
		}

		assertEquals(string_extractor.get_string_map(), expected);
		assertEquals(service.get_string_map(), expected);
	}

	static Stream<Arguments> test_search_inst_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05001000, "name");
						}},
						ProgramBuilder._X64,
						8,
						new HashMap<String, String>(){{
							put("0x401000",
									"488b15f9ffbf04"     // mov rdx, qword ptr ds:[0x5001000]
									+ "488910"           // mov qword ptr ds:[rax], rdx
									+ "48c7400804000000" // mov qword ptr ds:[rax+0x8], 0x4
									+ "c3");             // ret
							put("0x05001000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05001000, "name");
						}},
						ProgramBuilder._X64,
						8,
						new HashMap<String, String>(){{
							put("0x401000",
									"488b15f9ffbf04"           // mov rdx, qword ptr ds:[0x5001000]
									+ "48899000010000"         // mov qword ptr ds:[rax+0x100], rdx
									+ "48c7800801000004000000" // mov qword ptr ds:[rax+0x108], 0x4
									+ "c3");                   // ret
							put("0x05001000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05001000, "name");
						}},
						ProgramBuilder._X64,
						8,
						new HashMap<String, String>(){{
							put("0x401000",
									"488d15f9ffbf04"     // lea rdx, ds:[0x0000000005001000]
									+ "488910"           // mov qword ptr ds:[rax], rdx
									+ "48c7400804000000" // mov qword ptr ds:[rax+0x8], 0x4
									+ "c3");             // ret
							put("0x05001000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
						}},
						ProgramBuilder._X64,
						8,
						new HashMap<String, String>(){{
							put("0x401000",
									"488d15f9ffbf04"     // lea rdx, ds:[0x0000000005001000]
									+ "488bd3"           // mov rdx, rbx
									+ "488910"           // mov qword ptr ds:[rax], rdx
									+ "48c7400804000000" // mov qword ptr ds:[rax+0x8], 0x4
									+ "c3");             // ret
							put("0x05001000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
						}},
						ProgramBuilder._X64,
						8,
						new HashMap<String, String>(){{
							put("0x401000",
									"488d15f9ffbf04"     // lea rdx, ds:[0x0000000005001000]
									+ "4833d2"           // xor rdx, rdx
									+ "488910"           // mov qword ptr ds:[rax], rdx
									+ "48c7400804000000" // mov qword ptr ds:[rax+0x8], 0x4
									+ "c3");             // ret
							put("0x05001000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05001000, "name");
						}},
						ProgramBuilder._X86,
						4,
						new HashMap<String, String>(){{
							put("0xe31000",
									"8d1500100005"       // lea edx, ds:[0x05001000]
									+ "89542408"         // mov dword ptr ss:[esp+0x8], edx
									+ "c744240c04000000" // mov dword ptr ss:[esp+0xC], 0x4
									+ "c3");             // ret
							put("0x05001000", "6e616d656e616d65");
						}}
				)
			);
	}
}
