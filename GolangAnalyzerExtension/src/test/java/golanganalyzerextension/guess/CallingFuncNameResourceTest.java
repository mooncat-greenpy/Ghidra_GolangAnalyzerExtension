package golanganalyzerextension.guess;

import static org.junit.Assert.assertEquals;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class CallingFuncNameResourceTest extends AbstractGhidraHeadlessIntegrationTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
        builder.setBytes("0x801000", "c3");
        builder.createEmptyFunction("FUN_801000", "0x801000", 0x1, null);
        builder.setBytes("0x802000", "c3");
        builder.createEmptyFunction("FUN_802000", "0x802000", 0x1, null);
        builder.setBytes("0x803000", "c3");
        builder.createEmptyFunction("FUN_803000", "0x803000", 0x1, null);
        builder.setBytes("0x804000", "c3");
        builder.createEmptyFunction("FUN_804000", "0x804000", 0x1, null);
        builder.setBytes("0x805000", "c3");
        builder.createEmptyFunction("FUN_805000", "0x805000", 0x1, null);
        builder.setBytes("0x806000", "c3");
        builder.createEmptyFunction("FUN_806000", "0x806000", 0x1, null);
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_get_func_info_by_addr_params")
	public void test_get_func_info_by_addr(String file_name, long expected_addr, String expected_name, List<String> expected_calling) throws Exception {
		initialize(new HashMap<>());
		CallingFuncNameResource calling_func_name_res = new CallingFuncNameResource(file_name);
		FuncInfo info = calling_func_name_res.get_func_info_by_addr(expected_addr);
		assertEquals(info.get_addr(), expected_addr);
		assertEquals(info.get_name(), expected_name);
		assertEquals(info.get_calling(), expected_calling);
	}

	static Stream<Arguments> test_get_func_info_by_addr_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						"calling_func_name/calling_func.txt",
						0x402000,
						"_rt0_amd64",
						new LinkedList<>() {{
							add("runtime.rt0_go");
						}}
				),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						0x403000,
						"runtime.rt0_go",
						new LinkedList<>() {{
							add("runtime.settls");
							add("runtime.abort");
							add("runtime.check");
							add("runtime.args");
							add("runtime.osinit");
							add("runtime.schedinit");
							add("runtime.newproc");
							add("runtime.mstart");
						}}
				)
		);
	}

	@ParameterizedTest
	@MethodSource("test_calling_func_name_lists_params")
	public void test_calling_func_name_lists(String file_name, Map<String, List<List<String>>> expected) throws Exception {
		initialize(new HashMap<>());
		CallingFuncNameResource calling_func_name_res = new CallingFuncNameResource(file_name);
		for (Map.Entry<String, List<List<String>>> entry : expected.entrySet()) {
			assertEquals(calling_func_name_res.get_calling_func_name_lists(entry.getKey()), entry.getValue());
		}
	}

	static Stream<Arguments> test_calling_func_name_lists_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						"calling_func_name/calling_func.txt",
						new HashMap<>() {{
							put("_rt0_amd64_windows",
								new LinkedList<>() {{
									add(new LinkedList<>() {{
										add("_rt0_amd64");
									}});
								}}
							);
							put("_rt0_amd64",
								new LinkedList<>() {{
									add(new LinkedList<>() {{
										add("runtime.rt0_go");
									}});
								}}
							);
							put("runtime.rt0_go",
								new LinkedList<>() {{
									add(new LinkedList<>() {{
										add("runtime.settls");
										add("runtime.abort");
										add("runtime.check");
										add("runtime.args");
										add("runtime.osinit");
										add("runtime.schedinit");
										add("runtime.newproc");
										add("runtime.mstart");
									}});
								}}
							);
							put("runtime.schedinit",
								new LinkedList<>() {{
									add(new LinkedList<>() {{
										add("runtime.moduledataverify1");
										add("runtime.stackinit");
										add("runtime.mallocinit");
										add("runtime.getRandomData");
										add("runtime.mcommoninit");
										add("runtime.cpuinit");
										add("runtime.alginit");
										add("runtime.modulesinit");
										add("runtime.typelinksinit");
										add("runtime.itabsinit");
										add("runtime.goenvs");
										add("runtime.parsedebugvars");
										add("runtime.gcinit");
										add("runtime.lock2");
										add("runtime.nanotime1");
										add("runtime.gogetenv");
										add("runtime.atoi");
										add("runtime.procresize");
										add("runtime.unlock2");
										add("runtime.gcWriteBarrier");
										add("runtime.gcWriteBarrier");
										add("runtime.(*wbBuf).reset");
										add("runtime.throw");
										add("runtime.morestack");
										add("runtime.schedinit");
									}});
									add(new LinkedList<>() {{
										add("runtime.schedinit");
									}});
								}}
							);
						}}
				)
			);
	}

	@ParameterizedTest
	@MethodSource("test_calling_func_name_list_params")
	public void test_calling_func_name_list(String file_name, String func_name, int calling_num, List<String> expected) throws Exception {
		initialize(new HashMap<>());
		CallingFuncNameResource calling_func_name_res = new CallingFuncNameResource(file_name);
		assertEquals(calling_func_name_res.get_calling_func_name_list(func_name, calling_num), expected);
	}

	static Stream<Arguments> test_calling_func_name_list_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						"calling_func_name/calling_func.txt",
						"runtime.schedinit",
						22,
						new LinkedList<>() {{
							add("runtime.moduledataverify1");
							add("runtime.stackinit");
							add("runtime.mallocinit");
							add("runtime.getRandomData");
							add("runtime.mcommoninit");
							add("runtime.cpuinit");
							add("runtime.alginit");
							add("runtime.modulesinit");
							add("runtime.typelinksinit");
							add("runtime.itabsinit");
							add("runtime.goenvs");
							add("runtime.parsedebugvars");
							add("runtime.gcinit");
							add("runtime.lock2");
							add("runtime.nanotime1");
							add("runtime.gogetenv");
							add("runtime.atoi");
							add("runtime.procresize");
							add("runtime.unlock2");
							add("runtime.gcWriteBarrier");
							add("runtime.gcWriteBarrier");
							add("runtime.(*wbBuf).reset");
							add("runtime.throw");
							add("runtime.morestack");
							add("runtime.schedinit");
						}}),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						"runtime.schedinit",
						4,
						new LinkedList<>() {{
							add("runtime.schedinit");
						}}),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						"runtime.schedinit",
						5,
						null),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						"runtime.schedinit",
						21,
						null),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						"runtime.schedinit",
						29,
						null)
		);
	}

	@ParameterizedTest
	@MethodSource("test_get_func_name_by_placement_params")
	public void test_get_func_name_by_placement(String file_name, long addr, Map<Long, String> data, String expected) throws Exception {
		initialize(new HashMap<>());
		CallingFuncNameResource calling_func_name_res = new CallingFuncNameResource(file_name);

		Map<Address, String> input_map = new HashMap<>();
		for (Map.Entry<Long, String> entry : data.entrySet()) {
			input_map.put(program.getAddressFactory().getDefaultAddressSpace().getAddress(entry.getKey()), entry.getValue());
		}

		calling_func_name_res.get_func_name_by_placement(program.getListing().getFunctions(true), input_map);
		assertEquals(
			input_map.get(program.getAddressFactory().getDefaultAddressSpace().getAddress(addr)),
			expected);
	}

	static Stream<Arguments> test_get_func_name_by_placement_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						"calling_func_name/calling_func.txt",
						0x803000,
						new HashMap<>() {{
							put((long) 0x802000, "_rt0_amd64");
							put((long) 0x804000, "_rt0_amd64_windows");
						}},
						"runtime.rt0_go"
				),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						0x801000,
						new HashMap<>() {{
							put((long) 0x802000, "_rt0_amd64");
							put((long) 0x804000, "_rt0_amd64_windows");
						}},
						"runtime.schedinit"
				),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						0x805000,
						new HashMap<>() {{
							put((long) 0x802000, "_rt0_amd64");
							put((long) 0x804000, "_rt0_amd64_windows");
						}},
						"runtime.schedinit"
				)
		);
	}

	@ParameterizedTest
	@MethodSource("test_is_reliable_params")
	public void test_is_reliable(String file_name, long addr_value, Map<Long, String> data, boolean expected) throws Exception {
		initialize(new HashMap<>());
		CallingFuncNameResource calling_func_name_res = new CallingFuncNameResource(file_name);

		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_value);
		Map<Address, String> input_map = new HashMap<>();
		for (Map.Entry<Long, String> entry : data.entrySet()) {
			input_map.put(program.getAddressFactory().getDefaultAddressSpace().getAddress(entry.getKey()), entry.getValue());
		}
		assertEquals(calling_func_name_res.is_reliable(addr, input_map), expected);
	}

	static Stream<Arguments> test_is_reliable_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						"calling_func_name/calling_func.txt",
						0x404000,
						new HashMap<>() {{
							put((long) 0x401000, "runtime.schedinit");
							put((long) 0x402000, "_rt0_amd64");
							put((long) 0x403000, "runtime.rt0_go");
							put((long) 0x404000, "_rt0_amd64_windows");
							put((long) 0x405000, "runtime.schedinit");
							put((long) 0x406000, "runtime.memmove");
						}},
						true
				),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						0x404000,
						new HashMap<>() {{
							put((long) 0x401000, "test");
							put((long) 0x402000, "_rt0_amd64");
							put((long) 0x403000, "runtime.rt0_go");
							put((long) 0x404000, "_rt0_amd64_windows");
							put((long) 0x405000, "runtime.schedinit");
							put((long) 0x406000, "runtime.memmove");
						}},
						true
				),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						0x404000,
						new HashMap<>() {{
							put((long) 0x401000, "runtime.schedinit");
							put((long) 0x402000, "test");
							put((long) 0x403000, "runtime.rt0_go");
							put((long) 0x404000, "_rt0_amd64_windows");
							put((long) 0x405000, "runtime.schedinit");
							put((long) 0x406000, "runtime.memmove");
						}},
						false
				),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						0x404000,
						new HashMap<>() {{
							put((long) 0x401000, "runtime.schedinit");
							put((long) 0x402000, "_rt0_amd64");
							put((long) 0x403000, "runtime.rt0_go");
							put((long) 0x404000, "_rt0_amd64_windows");
							put((long) 0x405000, "runtime.schedinit");
							put((long) 0x406000, "test");
						}},
						false
				)
		);
	}

	@ParameterizedTest
	@MethodSource("test_collect_func_name_by_placement_params")
	public void test_collect_func_name_by_placement(String file_name, Map<Long, String> data, Map<Long, String> expected) throws Exception {
		initialize(new HashMap<>());
		CallingFuncNameResource calling_func_name_res = new CallingFuncNameResource(file_name);


		Map<Address, String> input_map = new HashMap<>();
		for (Map.Entry<Long, String> entry : data.entrySet()) {
			input_map.put(program.getAddressFactory().getDefaultAddressSpace().getAddress(entry.getKey()), entry.getValue());
		}
		Map<Address, String> expected_map = new HashMap<>();
		for (Map.Entry<Long, String> entry : expected.entrySet()) {
			expected_map.put(program.getAddressFactory().getDefaultAddressSpace().getAddress(entry.getKey()), entry.getValue());
		}
		calling_func_name_res.collect_func_name_by_placement(input_map);
		assertEquals(input_map, expected_map);
	}

	static Stream<Arguments> test_collect_func_name_by_placement_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						"calling_func_name/calling_func.txt",
						new HashMap<>() {{
							put((long) 0x401000, "runtime.schedinit");
							put((long) 0x402000, "_rt0_amd64");
							put((long) 0x403000, "runtime.rt0_go");
							put((long) 0x404000, "_rt0_amd64_windows");
							put((long) 0x405000, "runtime.schedinit");
							put((long) 0x406000, "runtime.memmove");
						}},
						new HashMap<>() {{
							put((long) 0x401000, "runtime.schedinit");
							put((long) 0x402000, "_rt0_amd64");
							put((long) 0x403000, "runtime.rt0_go");
							put((long) 0x404000, "_rt0_amd64_windows");
							put((long) 0x405000, "runtime.schedinit");
							put((long) 0x406000, "runtime.memmove");
						}}
				),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						new HashMap<>() {{
							put((long) 0x401000, "runtime.schedinit");
							put((long) 0x402000, "_rt0_amd64");
							put((long) 0x403000, "test");
							put((long) 0x404000, "_rt0_amd64_windows");
							put((long) 0x405000, "runtime.schedinit");
							put((long) 0x406000, "runtime.memmove");
						}},
						new HashMap<>() {{
							put((long) 0x401000, "runtime.schedinit");
							put((long) 0x402000, "_rt0_amd64");
							put((long) 0x403000, "runtime.rt0_go");
							put((long) 0x404000, "_rt0_amd64_windows");
							put((long) 0x405000, "runtime.schedinit");
							put((long) 0x406000, "runtime.memmove");
						}}
				),
				Arguments.of(
						"calling_func_name/calling_func.txt",
						new HashMap<>() {{
							put((long) 0x401000, "runtime.schedinit");
							put((long) 0x402000, "_rt0_amd64");
							put((long) 0x403000, "runtime.rt0_go");
							put((long) 0x404000, "test");
							put((long) 0x405000, "runtime.schedinit");
							put((long) 0x406000, "runtime.memmove");
						}},
						new HashMap<>() {{
							put((long) 0x401000, "runtime.schedinit");
							put((long) 0x402000, "_rt0_amd64");
							put((long) 0x403000, "runtime.rt0_go");
							put((long) 0x404000, "_rt0_amd64_windows");
							put((long) 0x405000, "runtime.schedinit");
							put((long) 0x406000, "runtime.memmove");
						}}
				)
		);
	}
}
