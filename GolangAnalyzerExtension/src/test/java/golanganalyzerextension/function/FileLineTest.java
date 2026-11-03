package golanganalyzerextension.function;

import static org.junit.Assert.assertEquals;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.Stream;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import ghidra.program.database.ProgramBuilder;
import ghidra.program.model.listing.Parameter;
import ghidra.program.model.listing.Program;
import ghidra.test.AbstractGhidraHeadlessIntegrationTest;
import ghidra.util.task.TaskMonitor;
import golanganalyzerextension.gobinary.GolangBinary;

public class FileLineTest extends AbstractGhidraHeadlessIntegrationTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		bytes_map.put("0x00600000", "fbffffff 00 00 01 04 00000000");
		bytes_map.put("0x0060000c", "00104000 00200000");
		bytes_map.put("0x00602000", "00104000");
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_get_address_params")
	public void test_get_address(long addr_value, int offset) throws Exception {
		initialize(new HashMap<String, String>(){{
			put("0x401000", "00000000000000000000000000000000");
		}});
		GolangBinary go_bin=new GolangBinary(program, "", TaskMonitor.DUMMY);

		FileLine file_line=new FileLine(go_bin.get_address(addr_value), offset, 0, "", 0, "go1.20");

		assertEquals(file_line.get_func_addr()+file_line.get_offset(), addr_value+offset);
	}

	static Stream<Arguments> test_get_address_params() throws Throwable {
		return Stream.of(
				Arguments.of(0x401000, 4),
				Arguments.of(0x401008, 5)
			);
	}

	@ParameterizedTest
	@MethodSource("test_get_file_name_params")
	public void test_get_file_name(String file_name, int line_num) throws Exception {
		initialize(new HashMap<String, String>());
		GolangBinary go_bin=new GolangBinary(program, "", TaskMonitor.DUMMY);

		FileLine file_line=new FileLine(go_bin.get_address(0x401000), 0, 0, file_name, line_num, "go1.20");

		assertEquals(file_line.get_file_name(), file_name);
	}

	static Stream<Arguments> test_get_file_name_params() throws Throwable {
		return Stream.of(
				Arguments.of("internal/cpu/cpu.go", 1),
				Arguments.of("runtime/runtime.go", 10)
			);
	}

	@ParameterizedTest
	@MethodSource("test_get_line_num_params")
	public void test_get_line_num(String file_name, int line_num) throws Exception {
		initialize(new HashMap<String, String>());
		GolangBinary go_bin=new GolangBinary(program, "", TaskMonitor.DUMMY);

		FileLine file_line=new FileLine(go_bin.get_address(0x401000), 0, 0, file_name, line_num, "go1.20");

		assertEquals(file_line.get_line_num(), line_num);
	}

	static Stream<Arguments> test_get_line_num_params() throws Throwable {
		return Stream.of(
				Arguments.of("internal/cpu/cpu.go", 1),
				Arguments.of("runtime/runtime.go", 10)
			);
	}

	@ParameterizedTest
	@MethodSource("test_to_string_params")
	public void test_to_string(String file_name, int line_num, String url) throws Exception {
		initialize(new HashMap<String, String>());
		GolangBinary go_bin=new GolangBinary(program, "", TaskMonitor.DUMMY);

		FileLine file_line=new FileLine(go_bin.get_address(0x401000), 0, 0, file_name, line_num, "go1.20");

		assertEquals(file_line.toString(), String.format("{@url %s}", url));
	}

	static Stream<Arguments> test_to_string_params() throws Throwable {
		return Stream.of(
				Arguments.of("internal/cpu/cpu.go", 1, "https://github.com/golang/go/blob/go1.20/src/internal/cpu/cpu.go#L1"),
				Arguments.of("runtime/runtime.go", 10, "https://github.com/golang/go/blob/go1.20/src/runtime/runtime.go#L10"),
				Arguments.of("github.com/tmp/pmt/v5@v5.3.0/batch.go", 1, "https://github.com/tmp/pmt/blob/v5.3.0/batch.go#L1"),
				Arguments.of("github.com/tmp/tmp-client@v0.0.0-20200128182646-c69cb7680fd4/repo_hook.go", 1, "https://github.com/tmp/tmp-client/blob/c69cb7680fd4/repo_hook.go#L1"),
				Arguments.of("github.com/tmp/tmp-module@v1.8.4/repo_tag.go", 1, "https://github.com/tmp/tmp-module/blob/v1.8.4/repo_tag.go#L1"),
				Arguments.of("golang.org/x/tools@v0.9.3/go/ssa/create.go", 1, "https://github.com/golang/tools/blob/v0.9.3/go/ssa/create.go#L1"),
				Arguments.of("/temp/pkg/mod/github.com/tmp/pmt/v5@v5.3.0/batch.go", 1, "https://github.com/tmp/pmt/blob/v5.3.0/batch.go#L1"),
				Arguments.of("/temp/pkg/mod/golang.org/x/tools@v0.9.3/go/ssa/create.go", 1, "https://github.com/golang/tools/blob/v0.9.3/go/ssa/create.go#L1")
			);
	}

	@Test
	public void test_serialize() throws Exception {
		initialize(new HashMap<String, String>());
		GolangBinary go_bin=new GolangBinary(program, "", TaskMonitor.DUMMY);

		FileLine file_line=new FileLine(go_bin.get_address(0x401000), 0, 0, "test.go", 4, "go1.20");
		ByteArrayOutputStream byte_out = new ByteArrayOutputStream();
		ObjectOutputStream out = new ObjectOutputStream(byte_out);
		out.writeObject(file_line);
		byte[] bytes=byte_out.toByteArray();
		ByteArrayInputStream byte_in = new ByteArrayInputStream(bytes);
		ObjectInputStream in = new ObjectInputStream(byte_in);
		FileLine file_line2=(FileLine)in.readObject();

		assertEquals(file_line.toString(), file_line2.toString());
	}

	@Test
	public void test_function_record_serialization() throws Exception {
		initialize(new HashMap<String, String>());
		GolangBinary go_bin = new GolangBinary(program, "", TaskMonitor.DUMMY);

		FileLine file_line = new FileLine(
				go_bin.get_address(0x401000),
				0x10,
				0x20,
				"runtime/runtime.go",
				123,
				"go1.20");

		Map<Integer, FileLine> file_line_map = new HashMap<>();
		file_line_map.put(0x10, file_line);

		Map<Integer, Long> frame_map = new HashMap<>();
		frame_map.put(0x20, 0x401020L);

		GolangFunctionRecord original = new GolangFunctionRecord(
				go_bin.get_address(0x401000),
				"runtime.testFunction",
				0x100,
				0,
				file_line_map,
				frame_map,
				new Parameter[0]);

		GolangFunctionRecord restored =
				new GolangFunctionRecord(go_bin, original.get_record());

		assertEquals(original.get_func_addr(), restored.get_func_addr());
		assertEquals(original.get_func_name(), restored.get_func_name());
		assertEquals(original.get_func_size(), restored.get_func_size());
		assertEquals(original.get_arg_size(), restored.get_arg_size());

		assertEquals(1, restored.get_file_line_comment_map().size());
		assertEquals(1, restored.get_frame_map().size());

		FileLine restored_file_line =
				restored.get_file_line_comment_map().get(0x10);

		assertEquals(file_line.get_func_addr(), restored_file_line.get_func_addr());
		assertEquals(file_line.get_offset(), restored_file_line.get_offset());
		assertEquals(file_line.get_size(), restored_file_line.get_size());
		assertEquals(file_line.get_file_name(), restored_file_line.get_file_name());
		assertEquals(file_line.get_line_num(), restored_file_line.get_line_num());
		assertEquals(file_line.toString(), restored_file_line.toString());

		assertEquals(
				Long.valueOf(0x401020L),
				restored.get_frame_map().get(0x20));
	}
}