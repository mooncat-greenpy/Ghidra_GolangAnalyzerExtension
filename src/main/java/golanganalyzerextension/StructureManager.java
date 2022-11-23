package golanganalyzerextension;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import golanganalyzerextension.UncommonType.UncommonMethod;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;


public class StructureManager {
	private GolangBinary go_bin;

	private DataTypeManager datatype_manager;
	private DatatypeHolder datatype_holder;
	private boolean is_go16;

	private boolean ok;

	public StructureManager(GolangBinary go_bin, Program program, GolangAnalyzerExtensionService service, boolean datatype_option) {
		this.go_bin=go_bin;

		if(!datatype_option) {
			return;
		}

		this.datatype_manager=program.getDataTypeManager();
		this.datatype_holder=new DatatypeHolder(go_bin, is_go16);

		if(!init_basig_golang_datatype()) {
			Logger.append_message("Failed to init datatype");
			return;
		}

		service.store_datatype_map(datatype_holder.get_datatype_map());

		this.ok=true;
		return;
	}

	boolean is_ok() {
		return ok;
	}

	void modify() {
		if(!ok) {
			Logger.append_message("Failed to setup StructureManager");
			return;
		}

		for(long key : datatype_holder.get_key_set()) {
			try {
				GolangDatatype go_datatype=datatype_holder.get_go_datatype_by_key(key);
				go_datatype.modify(datatype_holder);

				Category category=datatype_manager.createCategory(new CategoryPath(String.format("/Golang_%s", go_datatype.kind.name())));
				category.addDataType(go_datatype.get_datatype(), null);

				go_bin.set_comment(go_datatype.addr, ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, make_datatype_comment(go_datatype, datatype_holder));
			}catch(Exception e) {
				Logger.append_message(String.format("Error: %s", e.getMessage()));
			}
		}
	}

	String make_datatype_comment(GolangDatatype go_datatype, DatatypeHolder datatype_searcher) {
		String comment="Name: "+go_datatype.get_name()+"\n";

		comment+=go_datatype.get_kind().name()+":\n";
		for(DataTypeComponent field : go_datatype.get_datatype().getComponents()) {
			comment+=String.format("  +%#6x %#6x %s %s\n", field.getOffset(), field.getLength(), field.getDataType().getName(), field.getFieldName()!=null?field.getFieldName():"");
		}

		if(go_datatype.get_uncommon_type().isPresent()) {
			comment+="Method:\n";
			for(UncommonMethod method : go_datatype.get_uncommon_type().get().get_method_list()) {
				comment+=String.format("  +%s %#x %#x\n", method.get_name(), method.get_interface_method_addr().getOffset(), method.get_normal_method_addr().getOffset());
			}
		}

		return comment;
	}

	boolean init_basig_golang_datatype() {
		boolean is_go116=false;
		boolean is_go118=false;
		if(go_bin.ge_go_version("go1.16beta1")) {
			is_go116=true;
		}
		if(go_bin.ge_go_version("go1.18beta1")) {
			is_go118=true;
		}

		ByteBuffer buffer=ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(go_bin.get_gopclntab_base().getOffset());
		buffer.flip();
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		long reverse=buffer.getLong();
		buffer=ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(reverse);
		byte gopclntab_base_bytes[]=buffer.array();

		int pointer_size=go_bin.get_pointer_size();
		Address base_addr=null;
		while(true) {
			is_go16=false;

			if(pointer_size==4) {
				base_addr=go_bin.find_memory(base_addr, gopclntab_base_bytes, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00});
			}else {
				base_addr=go_bin.find_memory(base_addr, gopclntab_base_bytes, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff});
			}
			if(base_addr==null) {
				break;
			}

			// runtime/symtab.go
			long type_addr_value=0;
			long typelink_addr_value=0;
			long typelink_len=0;
			Address text_addr=null;
			if(is_go118) {
				type_addr_value=go_bin.get_address_value(base_addr, 35*pointer_size, pointer_size);
				typelink_addr_value=go_bin.get_address_value(base_addr, 42*pointer_size, pointer_size);
				typelink_len=go_bin.get_address_value(base_addr, 43*pointer_size, pointer_size);
				text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 22*pointer_size, pointer_size));
			}else if(is_go116) {
				type_addr_value=go_bin.get_address_value(base_addr, 35*pointer_size, pointer_size);
				typelink_addr_value=go_bin.get_address_value(base_addr, 40*pointer_size, pointer_size);
				typelink_len=go_bin.get_address_value(base_addr, 41*pointer_size, pointer_size);
				text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 22*pointer_size, pointer_size));
			}else {
				type_addr_value=go_bin.get_address_value(base_addr, 25*pointer_size, pointer_size);
				typelink_addr_value=go_bin.get_address_value(base_addr, 30*pointer_size, pointer_size);
				typelink_len=go_bin.get_address_value(base_addr, 31*pointer_size, pointer_size);

				Address tmp_type_addr=go_bin.get_address(type_addr_value);
				Address tmp_typelink_addr=go_bin.get_address(typelink_addr_value);
				try {
					analyze_type(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4));
				} catch(InvalidBinaryStructureException e) {
					type_addr_value=go_bin.get_address_value(base_addr, 25*pointer_size, pointer_size);
					typelink_addr_value=go_bin.get_address_value(base_addr, 27*pointer_size, pointer_size);
					typelink_len=go_bin.get_address_value(base_addr, 28*pointer_size, pointer_size);
					tmp_type_addr=go_bin.get_address(type_addr_value);
					tmp_typelink_addr=go_bin.get_address(typelink_addr_value);
				}
				try {
					analyze_type(tmp_type_addr, go_bin.get_address_value(tmp_typelink_addr, 0, 4));
				} catch(InvalidBinaryStructureException e) {
					is_go16=true;
					type_addr_value=0;
					typelink_addr_value=go_bin.get_address_value(base_addr, 25*pointer_size, pointer_size);
					typelink_len=go_bin.get_address_value(base_addr, 26*pointer_size, pointer_size);
				}
				text_addr=go_bin.get_address(go_bin.get_address_value(base_addr, 12*pointer_size, pointer_size));
			}

			Address type_addr=go_bin.get_address(type_addr_value);
			Address typelink_addr=go_bin.get_address(typelink_addr_value);

			if((!go_bin.is_valid_address(type_addr) && !is_go16) || !go_bin.is_valid_address(typelink_addr) || !text_addr.equals(go_bin.get_section(".text")))
			{
				base_addr=go_bin.get_address(base_addr, 4);
				if(base_addr==null) {
					break;
				}
				continue;
			}

			datatype_holder=new DatatypeHolder(go_bin, is_go16);

			for(long i=0;i<typelink_len;i++)
			{
				long offset=0;
				if(is_go16) {
					offset=go_bin.get_address_value(typelink_addr, pointer_size*i, pointer_size)-type_addr.getOffset();
				}else {
					offset=go_bin.get_address_value(typelink_addr, i*4, 4);
				}
				try {
					analyze_type(type_addr, offset);
				} catch(InvalidBinaryStructureException e) {
					Logger.append_message(String.format("Failed to analyze type: addr=%x, offset=%x message=%s", type_addr.getOffset(), offset, e.getMessage()));
				}
			}

			base_addr=go_bin.get_address(base_addr, 4);
			if(base_addr==null) {
				break;
			}
		}

		if(datatype_holder.get_datatype_map().size()==0)
		{
			return false;
		}
		return true;
	}

	boolean analyze_type(Address type_base_addr, long offset) throws InvalidBinaryStructureException {
		if(datatype_holder.contain_key(offset)) {
			return true;
		}

		GolangDatatype go_datatype=GolangDatatype.create_by_parsing(go_bin, type_base_addr, offset, is_go16);
		datatype_holder.put_datatype(offset, go_datatype);

		for(long dependence_type_key : go_datatype.dependence_type_key_list) {
			analyze_type(type_base_addr, dependence_type_key);
		}
		go_datatype.make_datatype(datatype_holder);
		datatype_holder.replace_datatype(offset, go_datatype);

		return true;
	}
}
