package golanganalyzerextension.guess;

import static org.junit.Assert.assertEquals;

import java.util.LinkedList;
import java.util.List;
import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

public class CommonCallingFuncNameFileTest {

	@ParameterizedTest
	@MethodSource("test_get_func_name_list_params")
	public void test_get_func_name_list(String version, String func_name, List<String> expected_pre, List<String> expected_post) throws Exception {
		CommonCallingFuncNameFile calling_func_name_file = new CommonCallingFuncNameFile(version);

		assertEquals(calling_func_name_file.get_pre_func_name_list(func_name), expected_pre);
		assertEquals(calling_func_name_file.get_post_func_name_list(func_name), expected_post);
	}

	static Stream<Arguments> test_get_func_name_list_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						"go1.18.9",
						"_rt0_amd64_windows",
						new LinkedList<>() {{
							add("_rt0_amd64");
						}},
						new LinkedList<>() {{
							add("_rt0_amd64");
						}}
				),
				Arguments.of(
						"go1.15beta1",
						"runtime.debugCallV1",
						new LinkedList<>() {{
						}},
						new LinkedList<>() {{
						}}
				),
				Arguments.of(
						"go1.16rc1",
						"runtime.hashGrow",
						new LinkedList<>() {{
							add("runtime.makeBucketArray");
							add("runtime.gcWriteBarrier");
							add("runtime.newobject");
							add("runtime.gcWriteBarrier");
						}},
						new LinkedList<>() {{
						}}
				),
				Arguments.of(
					"go1.19",
					"runtime.rt0_go",
					new LinkedList<>() {{
					}},
					new LinkedList<>() {{
						add("runtime.check");
						add("runtime.args");
						add("runtime.osinit");
						add("runtime.schedinit");
						add("runtime.newproc");
						add("runtime.mstart");
					}}
				),
				Arguments.of(
					"go1.24rc1",
					"runtime.rt0_go",
					new LinkedList<>() {{
					}},
					new LinkedList<>() {{
						add("runtime.check");
						add("runtime.args");
						add("runtime.osinit");
						add("runtime.schedinit");
						add("runtime.newproc");
						add("runtime.mstart");
						add("runtime.abort");
					}}
				),
				Arguments.of(
					"go1.15beta1",
					"test",
					new LinkedList<>() {{
					}},
					new LinkedList<>() {{
					}}
				)
		);
	}
}
