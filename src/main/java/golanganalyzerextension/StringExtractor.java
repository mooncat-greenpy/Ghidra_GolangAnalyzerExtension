package golanganalyzerextension;

import java.util.HashMap;
import java.util.Map;

import ghidra.program.model.address.Address;
import ghidra.program.model.mem.MemoryBlock;

public class StringExtractor {

	private GolangBinary go_bin;

	private Map<Long, String> string_map;

	public StringExtractor(GolangBinary go_bin, GolangAnalyzerExtensionService service) {
		this.go_bin=go_bin;

		string_map=new HashMap<Long, String>();

		search_memory();
		search_inst();

		service.store_string_map(string_map);
	}

	public Map<Long, String> get_string_map(){
		return string_map;
	}

	public void modify() {
		for(Map.Entry<Long, String> entry : string_map.entrySet()) {
			go_bin.create_label(go_bin.get_address(entry.getKey()), String.format("gos_%s_%x", entry.getValue(), entry.getKey()));
		}
	}

	private String check_string(Address addr) {
		int pointer_size=go_bin.get_pointer_size();

		if(!go_bin.is_valid_address(addr) || !go_bin.is_valid_address(addr.add(pointer_size))) {
			return null;
		}
		long str_addr_value=go_bin.get_address_value(addr, pointer_size);
		if(!go_bin.is_valid_address(str_addr_value)) {
			return null;
		}
		long str_len=go_bin.get_address_value(addr, pointer_size, pointer_size);
		if(str_len<=0 || str_len>=0x1000) {
			return null;
		}
		if(go_bin.is_valid_address(addr.add(pointer_size*2))) {
			long str_len2=go_bin.get_address_value(addr, pointer_size*2, pointer_size);
			if(str_len==str_len2) {
				return null;
			}
		}

		String str=go_bin.read_string(go_bin.get_address(str_addr_value), (int)str_len);
		if(str.length()!=str_len) {
			return null;
		}

		return str;
	}

	private void search_memory() {
		int pointer_size=go_bin.get_pointer_size();

		for (MemoryBlock mb : go_bin.get_memory_blocks()) {
			Address search_addr=mb.getStart();
			while(go_bin.is_valid_address(search_addr) && search_addr.getOffset()<mb.getEnd().getOffset()) {
				String str=check_string(search_addr);
				if(str==null) {
					search_addr=search_addr.add(pointer_size);
					continue;
				}

				string_map.put(search_addr.getOffset(), str);
				search_addr=search_addr.add(pointer_size*2);
			}
		}
	}

	private void search_inst() {
		// LEA        RCX,[0xXXXXXXXX]              : 0xXXXXXXXX: "name"
		// MOV        EDI,0x4

		// LEA        RBX,[0xXXXXXXXX]              : 0xXXXXXXXX: "name"
		// MOV        qword ptr [RSP + 0x180],RBX
		// MOV        qword ptr [RSP + 0x188],0x4

		// MOV        qword ptr [RAX + 0x8],0x4
		// CMP        dword ptr [0xYYYYYYYY],0x0
		// JNZ        0xZZZZZZZZ
		// LEA        RDX,[0xXXXXXXXX]              : 0xXXXXXXXX: "name"
		// MOV        qword ptr [RAX],RDX

		// LEA        RBX,[0xXXXXXXXX]              : 0xXXXXXXXX: &"name", 4
	}
}
