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

public class GuessedFuncNamesTest extends AbstractGhidraHeadlessIntegrationTest {

	protected Program program;

	protected void initialize(Map<String, String> bytes_map) throws Exception {
		ProgramBuilder builder=new ProgramBuilder("test", ProgramBuilder._X86, null);
		for(Map.Entry<String, String> entry : bytes_map.entrySet()) {
			builder.setBytes(entry.getKey(), entry.getValue());
		}
		program = builder.getProgram();
	}

	@ParameterizedTest
	@MethodSource("test_guessed_func_names_params")
	public void test_guessed_func_names(long addr_value, String expected_name, GuessedFuncNames.GuessedConfidence expected_confidence) throws Exception {
		initialize(new HashMap<>());
		GuessedFuncNames guessed_names_holder = new GuessedFuncNames();
		Address addr = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_value);
		assertEquals(guessed_names_holder.size(), 0);
		guessed_names_holder.put(addr, expected_name, expected_confidence);
		assertEquals(guessed_names_holder.get_name(addr), expected_name);
		assertEquals(guessed_names_holder.get_confidence(addr), expected_confidence);
		assertEquals(guessed_names_holder.size(), 1);
	}

	static Stream<Arguments> test_guessed_func_names_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						0x401000,
						"runtime.schedinit",
						GuessedFuncNames.GuessedConfidence.VERY_LOW
				),
				Arguments.of(
						0x402000,
						"_rt0_amd64",
						GuessedFuncNames.GuessedConfidence.LOW
				),
				Arguments.of(
						0x403000,
						"runtime.rt0_go",
						GuessedFuncNames.GuessedConfidence.MEDIUM
				),
				Arguments.of(
						0x404000,
						"_rt0_amd64_windows",
						GuessedFuncNames.GuessedConfidence.HIGH
				),
				Arguments.of(
						0x405000,
						"runtime.schedinit",
						GuessedFuncNames.GuessedConfidence.VERY_HIGH
				)
		);
	}

	@ParameterizedTest
	@MethodSource("test_guessed_func_names_confidence_params")
	public void test_guessed_func_names_confidence(long addr_value_1, String name_1, GuessedFuncNames.GuessedConfidence confidence_1, long addr_value_2, String name_2, GuessedFuncNames.GuessedConfidence confidence_2, String expected_name) throws Exception {
		initialize(new HashMap<>());
		GuessedFuncNames guessed_names_holder = new GuessedFuncNames();
		Address addr_1 = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_value_1);
		Address addr_2 = program.getAddressFactory().getDefaultAddressSpace().getAddress(addr_value_2);
		guessed_names_holder.put(addr_1, name_1, confidence_1);
		guessed_names_holder.put(addr_2, name_2, confidence_2);
		assertEquals(guessed_names_holder.get_name(addr_2), expected_name);
	}

	static Stream<Arguments> test_guessed_func_names_confidence_params() throws Throwable {
		return Stream.of(
				Arguments.of(
						0x401000,
						"runtime.schedinit_1",
						GuessedFuncNames.GuessedConfidence.VERY_LOW,
						0x401000,
						"runtime.schedinit_2",
						GuessedFuncNames.GuessedConfidence.VERY_LOW,
						"runtime.schedinit_2"
				),
				Arguments.of(
						0x402000,
						"_rt0_amd64_1",
						GuessedFuncNames.GuessedConfidence.VERY_HIGH,
						0x402000,
						"_rt0_amd64_2",
						GuessedFuncNames.GuessedConfidence.VERY_HIGH,
						"_rt0_amd64_2"
				),
				Arguments.of(
						0x403000,
						"runtime.rt0_go_1",
						GuessedFuncNames.GuessedConfidence.LOW,
						0x403000,
						"runtime.rt0_go_2",
						GuessedFuncNames.GuessedConfidence.VERY_LOW,
						"runtime.rt0_go_1"
				),
				Arguments.of(
						0x404000,
						"_rt0_amd64_windows_1",
						GuessedFuncNames.GuessedConfidence.VERY_LOW,
						0x404000,
						"_rt0_amd64_windows_2",
						GuessedFuncNames.GuessedConfidence.VERY_HIGH,
						"_rt0_amd64_windows_2"
				),
				Arguments.of(
						0x405000,
						"runtime.schedinit_1",
						GuessedFuncNames.GuessedConfidence.MEDIUM,
						0x405000,
						"runtime.schedinit_2",
						GuessedFuncNames.GuessedConfidence.HIGH,
						"runtime.schedinit_2"
				)
		);
	}
}
