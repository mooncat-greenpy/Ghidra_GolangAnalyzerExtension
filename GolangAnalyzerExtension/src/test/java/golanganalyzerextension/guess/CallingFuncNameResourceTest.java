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
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class CallingFuncNameResourceTest extends AbstractGhidraHeadlessIntegrationTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
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
						"calling_func.txt",
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
						"calling_func.txt",
						"runtime.schedinit",
						15,
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
						"calling_func.txt",
						"runtime.schedinit",
						3,
						new LinkedList<>() {{
							add("runtime.schedinit");
						}})
		);
	}
}
