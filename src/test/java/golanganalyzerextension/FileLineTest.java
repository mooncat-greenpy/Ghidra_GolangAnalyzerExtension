package golanganalyzerextension;

import static org.junit.Assert.assertEquals;

import java.util.stream.Stream;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ghidra.test.AbstractGhidraHeadlessIntegrationTest;

public class FileLineTest extends AbstractGhidraHeadlessIntegrationTest {

	@ParameterizedTest
	@MethodSource("test_get_file_name_params")
	public void test_get_file_name(String file_name, int line_num) throws Exception {
		FileLine file_line=new FileLine(file_name, line_num);

		assertEquals(file_line.get_file_name(), file_name);
	}

	static Stream<Arguments> test_get_file_name_params() throws Throwable {
		return Stream.of(
				Arguments.of("cpu/cpu.go", 1),
				Arguments.of("runtime/runtime.go", 10)
			);
	}

	@ParameterizedTest
	@MethodSource("test_get_line_num_params")
	public void test_get_line_num(String file_name, int line_num) throws Exception {
		FileLine file_line=new FileLine(file_name, line_num);

		assertEquals(file_line.get_line_num(), line_num);
	}

	static Stream<Arguments> test_get_line_num_params() throws Throwable {
		return Stream.of(
				Arguments.of("cpu/cpu.go", 1),
				Arguments.of("runtime/runtime.go", 10)
			);
	}

	@ParameterizedTest
	@MethodSource("test_to_string_params")
	public void test_to_string(String file_name, int line_num) throws Exception {
		FileLine file_line=new FileLine(file_name, line_num);

		assertEquals(file_line.toString(), String.format("%s:%d", file_name, line_num));
	}

	static Stream<Arguments> test_to_string_params() throws Throwable {
		return Stream.of(
				Arguments.of("cpu/cpu.go", 1),
				Arguments.of("runtime/runtime.go", 10)
			);
	}
}