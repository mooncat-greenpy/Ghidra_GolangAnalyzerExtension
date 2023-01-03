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
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.service.GolangAnalyzerExtensionDummyService;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;
import golanganalyzerextension.string.GolangString;
import golanganalyzerextension.string.StringExtractor;

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

		Map<Long, GolangString> str_map=string_extractor.get_string_map();
		Map<Long, GolangString> serv_str_map=service.get_string_map();
		assertEquals(str_map.size(), expected.size());
		assertEquals(serv_str_map.size(), expected.size());
		for(long key : expected.keySet()) {
			assertEquals(str_map.get(key).get_str(), expected.get(key));
			assertEquals(serv_str_map.get(key).get_str(), expected.get(key));
		}
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

		Map<Long, GolangString> str_map=string_extractor.get_string_map();
		Map<Long, GolangString> serv_str_map=service.get_string_map();
		assertEquals(str_map.size(), expected.size());
		assertEquals(serv_str_map.size(), expected.size());
		for(long key : expected.keySet()) {
			assertEquals(str_map.get(key).get_str(), expected.get(key));
			assertEquals(serv_str_map.get(key).get_str(), expected.get(key));
		}
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
				/*Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05001000, "name");
						}},
						ProgramBuilder._X64,
						8,
						new HashMap<String, String>(){{
							put("0x821000",
									"488d0df9ff7d04"     // lea rcx, ds:[0x0000000005001000]
									+ "bf04000000"       // mov edi, 4
									+ "c3");             // ret
							put("0x05001000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05000500, "name");
						}},
						ProgramBuilder._X64,
						8,
						new HashMap<String, String>(){{
							put("0x821000",
									"488d1df9f47d04"     // lea rbx, ds:[0x0000000005000500]
									+ "c3");             // ret
							put("0x05000500", "0010000500000000000400000000000000");
							put("0x05001000", "6e616d656e616d65");
						}}
				),*/
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
				)/*,
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0x05001000, "name");
						}},
						ProgramBuilder._ARM,
						4,
						new HashMap<String, String>(){{
							put("0x99a00",
									"ec369fe5"     // ldr r3,[0x9a0f4]
									+ "0c308de5"   // str r3,[sp,#0xc]
									+ "0440a0e3"   // mov r4,#0x4
									+ "10408de5"   // str r4,[sp,#0x10]
									+ "14f09de4"); // ldr pc,[sp],#14
							put("0x9a0f4", "0010000500");
							put("0x05001000", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0xb63c0, "name");
						}},
						ProgramBuilder._AARCH64,
						8,
						new HashMap<String, String>(){{
							put("0x0008f6dc",
							        "220100f0"     // adrp x2,0xb6000
									+ "42000f91"   // add x2=>DAT_000b63c0,x2,#0x3c0
									+ "e3037eb2"   // orr x3,xzr,#0x4
									+ "c0035fd6"); // ret
							put("0xb63c0", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0xb6683, "golang");
						}},
						ProgramBuilder._AARCH64,
						8,
						new HashMap<String, String>(){{
							put("0x0008f6f4",
							        "e1077fb2"     // orr x1,xzr,#0x6
							        + "010400f9"   // str x1,[x0, #0x8]
									+ "5b070090"   // adrp x27,0x177000
									+ "7bc30191"   // add x27,x27,#0x70
									+ "620340b9"   // ldr w2,[x27]=>DAT_00177070
									+ "a2000035"   // cbnz w2,LAB_0008f71c
									+ "240100f0"   // adrp x4,0xb6000
									+ "840c1a91"   // add x4=>DAT_000b6683,x4,#0x683
									+ "040000f9"   // str x4=>DAT_000b6683,[x0]
									+ "c0035fd6"); // ret
							put("0xb6683", "676f6c616e67676f");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0xd1c6f, "name");
						}},
						ProgramBuilder._MIPS,
						4,
						new HashMap<String, String>(){{
							put("0xb2440",
									"3c04000d"     // lui a0,0xd
									+ "24841c6f"   // addiu a0,a0,0x1c6f
									+ "afa4000c"   // sw a0=>DAT_000d1c6f,0xc(sp)
									+ "24040004"   // li a0,0x4
									+ "afa40010"   // sw a0,0x10(sp)
									+ "03e00008"); // jr ra
							put("0xd1c6f", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0xd62bf, "name");
						}},
						ProgramBuilder._MIPS_6432,
						8,
						new HashMap<String, String>(){{
							put("0xb6e00",
									"3c04000d"     // lui a0,0xd
									+ "009c202d"   // daddu a0,a0,gp
									+ "648462bf"   // daddiu a0,a0,0x62bf
									+ "ffa40018"   // sd a0=>DAT_000d62bf,0x18(sp)
									+ "64040004"   // daddiu a0,zero,0x4
									+ "ffa40020"   // sd a0,0x20(sp)
									+ "03e00008"); // jr ra
							put("0xd62bf", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0xd6625, "name");
						}},
						ProgramBuilder._MIPS_6432,
						8,
						new HashMap<String, String>(){{
							put("0xb6e20",
									"dfb40028"     // ld s4,0x28(sp)
									+ "64020004"   // daddiu v0,zero,0x4
									+ "fe820008"   // sd v0,0x8(s4)
									+ "3c17001a"   // lui s7,0x1a
									+ "02fcb82d"   // daddu s7,s7,gp
									+ "9ee397c0"   // lwu v1,-0x6840(s7)
									+ "14600007"   // bne v1,zero,LAB_000b6e58
									+ "3c01000d"   // lui at,0xd
									+ "003c082d"   // daddu at,at,gp
									+ "64216625"   // daddiu at,at,0x6625
									+ "fe810000"   // sd at=>DAT_000d6625,0x0(s4)
									+ "03e00008"); // jr ra
							put("0xd6625", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0xb6299, "name");
						}},
						ProgramBuilder._PPC_64,
						8,
						new HashMap<String, String>(){{
							put("0x922f4",
									"3ca0000b"     // lis r5,0xb
									+ "38a56299"   // addi r5,r5,0x6299
									+ "38c00004"   // li r6,0x4
									+ "4e800020"); // blr
							put("0xb6299", "6e616d656e616d65");
						}}
				),
				Arguments.of(
						new HashMap<Long, String>(){{
							put((long)0xb6607, "name");
						}},
						ProgramBuilder._PPC_64,
						8,
						new HashMap<String, String>(){{
							put("0x92310",
									"f8 83 00 08"     // std r4,0x8(r3)
									+ "3c e0 00 0b"   // lis r7,0xb
									+ "38 e7 66 07"   // addi r7,r7,0x6607
									+ "f8 e3 00 00"   // std r7=>DAT_000b6607,0x0(r3)
									+ "4e 80 00 20"); // blr
							put("0xb6607", "6e616d656e616d65");
						}}
				)*/
			);
	}
}
