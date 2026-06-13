package golanganalyzerextension;

import java.util.List;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.address.AddressSpace;
import ghidra.program.model.listing.Data;
import ghidra.program.model.listing.Function;
import ghidra.program.model.listing.FunctionIterator;
import ghidra.program.model.listing.Instruction;
import ghidra.program.model.listing.Listing;
import ghidra.program.model.listing.Program;
import ghidra.program.model.scalar.Scalar;
import ghidra.program.model.symbol.Equate;
import ghidra.program.model.symbol.EquateTable;
import ghidra.program.model.symbol.RefType;
import ghidra.program.model.symbol.Reference;
import ghidra.program.model.symbol.ReferenceManager;
import ghidra.program.model.symbol.SourceType;
import ghidra.program.model.symbol.Symbol;
import ghidra.program.model.symbol.SymbolTable;
import golanganalyzerextension.datatype.GolangDatatypeRecord;
import golanganalyzerextension.function.GolangFunctionRecord;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;

// Walks WASM function bodies and attaches DATA references from i32.const/i64.const
// instructions to their linear-memory targets when those targets have a defined data
// item or a labeled symbol. Without this, Go's WASM pointer loads decompile as raw
// constants like `0x36878`; with it the decompiler prints the symbol name instead.
public class WasmReferenceLinker {

	// Depends on https://github.com/nneonneo/ghidra-wasm-plugin
	private static final long MEMORY_LOW = 0x1000L;
	private static final long MEMORY_HIGH = 0x7f000000L;

	private final Program program;
	private final GolangBinary go_bin;
	private final GolangAnalyzerExtensionService service;

	public WasmReferenceLinker(Program program, GolangBinary go_bin, GolangAnalyzerExtensionService service) {
		this.program = program;
		this.go_bin = go_bin;
		this.service = service;
	}

	public void link() {
		if (!go_bin.is_wasm()) {
			return;
		}
		ReferenceManager ref_mgr = program.getReferenceManager();
		SymbolTable sym_tab = program.getSymbolTable();
		EquateTable eq_tab = program.getEquateTable();
		Listing listing = program.getListing();
		AddressSpace ram = program.getAddressFactory().getAddressSpace("ram");
		if (ram == null) {
			return;
		}

		List<GolangFunctionRecord> gofuncs = service.get_function_list();
		for (GolangFunctionRecord gofunc : gofuncs) {
			Function func=go_bin.get_function(gofunc.get_func_addr()).orElse(null);
			if (func == null) {
				continue;
			}
			Address entry = func.getEntryPoint();
			Instruction inst = listing.getInstructionAt(entry);
			while (inst != null && func.getBody().contains(inst.getAddress())) {
				try_link(inst, ram, listing, sym_tab, ref_mgr, eq_tab);
				inst = inst.getNext();
			}
		}
	}

	private void try_link(Instruction inst, AddressSpace ram, Listing listing, SymbolTable sym_tab, ReferenceManager ref_mgr, EquateTable eq_tab) {
		String mnem = inst.getMnemonicString();
		if (!mnem.equals("i64.const") && !mnem.equals("i32.const")) {
			return;
		}
		Map<Long, GolangDatatypeRecord> datatype_map = service.get_datatype_map();
		int num_ops = inst.getNumOperands();
		for (int op = 0; op < num_ops; op++) {
			Object[] objs = inst.getOpObjects(op);
			for (Object o : objs) {
				if (!(o instanceof Scalar)) {
					continue;
				}
				long val = ((Scalar) o).getUnsignedValue();
				if ((val < MEMORY_LOW || val >= MEMORY_HIGH) && !datatype_map.containsKey(val)) {
					continue;
				}
				Address target;
				try {
					target = ram.getAddress(val);
				} catch (Exception e) {
					continue;
				}
				String label = pick_label(target, listing, sym_tab);
				if (label == null) {
					continue;
				}
				if (!reference_exists(inst, target, op, ref_mgr)) {
					ref_mgr.addMemoryReference(inst.getAddress(), target, RefType.DATA, SourceType.ANALYSIS, op);
				}
				attach_equate(inst, op, val, label, eq_tab);
				return;
			}
		}
	}

	private String pick_label(Address target, Listing listing, SymbolTable sym_tab) {
		Symbol s = sym_tab.getPrimarySymbol(target);
		if (s == null) {
			return null;
		}

		SourceType src = s.getSource();
		if (src == SourceType.USER_DEFINED || src == SourceType.IMPORTED) {
			return s.getName();
		}

		Data defined = listing.getDefinedDataAt(target);
		if (defined != null) {
			return s.getName();
		}

		return null;
	}

	private void attach_equate(Instruction inst, int op, long val, String label, EquateTable eq_tab) {
		// Prefix avoids decompiler ambiguity between the equate (a substitution for a
		// scalar value) and a same-named code/data symbol.
		String eq_name = "&" + label;
		Equate eq = eq_tab.getEquate(eq_name);
		try {
			if (eq == null) {
				eq = eq_tab.createEquate(eq_name, val);
			} else if (eq.getValue() != val) {
				return;
			}
			eq.addReference(inst.getAddress(), op);
		} catch (Exception e) {
			// silent: invalid name or duplicate reference
		}
	}

	private boolean reference_exists(Instruction inst, Address target, int op_idx, ReferenceManager ref_mgr) {
		Reference[] refs = ref_mgr.getReferencesFrom(inst.getAddress(), op_idx);
		for (Reference r : refs) {
			if (r.getToAddress().equals(target)) {
				return true;
			}
		}
		return false;
	}
}
