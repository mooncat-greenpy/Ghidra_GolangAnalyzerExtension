package golanganalyzerextension;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.Program;
import golanganalyzerextension.datatype.GolangDatatype;
import golanganalyzerextension.datatype.UncommonType.UncommonMethod;
import golanganalyzerextension.exceptions.InvalidBinaryStructureException;
import golanganalyzerextension.gobinary.GolangBinary;
import golanganalyzerextension.gobinary.ModuleData;
import golanganalyzerextension.gobinary.exceptions.BinaryAccessException;
import golanganalyzerextension.log.Logger;
import golanganalyzerextension.service.GolangAnalyzerExtensionService;


public class StructureManager {
	private GolangBinary go_bin;

	private DatatypeHolder datatype_holder;

	private boolean ok;

	public StructureManager(GolangBinary go_bin, Program program, GolangAnalyzerExtensionService service, boolean datatype_option) {
		this.go_bin=go_bin;

		if(!datatype_option) {
			return;
		}

		this.datatype_holder=new DatatypeHolder(go_bin, false);

		if(!init_basig_golang_datatype()) {
			Logger.append_message("Failed to init datatype");
			return;
		}

		service.store_datatype_map(datatype_holder.get_datatype_map());

		this.ok=true;
		return;
	}

	public boolean is_ok() {
		return ok;
	}

	public void modify() {
		if(!ok) {
			Logger.append_message("Failed to setup StructureManager");
			return;
		}

		for(long key : datatype_holder.get_key_set()) {
			try {
				GolangDatatype go_datatype=datatype_holder.get_go_datatype_by_key(key);
				go_datatype.modify(datatype_holder);

				go_bin.add_datatype(go_datatype.get_category_path(), go_datatype.get_datatype());

				go_bin.set_comment(go_datatype.get_addr(), ghidra.program.model.listing.CodeUnit.PLATE_COMMENT, make_datatype_comment(go_datatype, datatype_holder));
			}catch(Exception e) {
				Logger.append_message(String.format("Error: %s", e.getMessage()));
			}
		}
	}

	private String make_datatype_comment(GolangDatatype go_datatype, DatatypeHolder datatype_searcher) {
		String comment="Name: "+go_datatype.get_name()+"\n";

		comment+=go_datatype.get_kind().name()+":\n";
		DataTypeComponent[] components=go_datatype.get_datatype().getComponents();
		final int MAX_FIELD_NUM=100;
		for(int i=0; i<components.length && i<MAX_FIELD_NUM; i++) {
			DataTypeComponent field=components[i];
			comment+=String.format("  +%#6x %#6x %s %s\n", field.getOffset(), field.getLength(), field.getDataType().getName(), field.getFieldName()!=null?field.getFieldName():"");
		}

		if(go_datatype.get_uncommon_type().isPresent()) {
			comment+="Method:\n";
			for(UncommonMethod method : go_datatype.get_uncommon_type().get().get_method_list()) {
				comment+=String.format("  +%s %s %s\n", method.get_name(), method.get_interface_method_addr().orElse(null), method.get_normal_method_addr().orElse(null));
			}
		}

		return comment;
	}

	private boolean init_basig_golang_datatype() {
		ByteBuffer buffer=ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(go_bin.get_pcheader_base().getOffset());
		buffer.flip();
		buffer.order(ByteOrder.LITTLE_ENDIAN);
		long reverse=buffer.getLong();
		buffer=ByteBuffer.allocate(Long.BYTES);
		buffer.putLong(reverse);
		byte gopclntab_base_bytes[]=buffer.array();

		int pointer_size=go_bin.get_pointer_size();
		Address base_addr=null;
		while(true) {
			try {
				if(pointer_size==4) {
					base_addr=go_bin.find_memory(base_addr, gopclntab_base_bytes, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0x00,(byte)0x00,(byte)0x00,(byte)0x00}).orElse(null);
				}else {
					base_addr=go_bin.find_memory(base_addr, gopclntab_base_bytes, new byte[] {(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff,(byte)0xff}).orElse(null);
				}
				if(base_addr==null) {
					break;
				}

				ModuleData module_data;
				try {
					module_data=new ModuleData(go_bin, base_addr);
				} catch(InvalidBinaryStructureException e) {
					Logger.append_message(String.format("Failed to get module data: %s", e.getMessage()));
					base_addr=go_bin.get_address(base_addr, 4);
					continue;
				}

				Address type_addr=module_data.get_type_addr();
				Address typelink_addr=module_data.get_typelink_addr();
				long typelink_len=module_data.get_typelink_len();
				boolean is_go16=module_data.get_is_go16();
				datatype_holder=new DatatypeHolder(go_bin, is_go16);

				for(long i=0;i<typelink_len;i++)
				{
					long offset;
					if(is_go16) {
						offset=go_bin.get_address_value(typelink_addr, pointer_size*i, pointer_size)-type_addr.getOffset();
					}else {
						offset=go_bin.get_address_value(typelink_addr, i*4, 4);
					}
					try {
						analyze_type(type_addr, offset, is_go16);
					} catch(InvalidBinaryStructureException e) {
						Logger.append_message(String.format("Failed to analyze type: addr=%s, offset=%x, message=%s", type_addr, offset, e.getMessage()));
					}
				}

				base_addr=go_bin.get_address(base_addr, 4);
			} catch (BinaryAccessException e) {
				Logger.append_message(String.format("Failed to get datatypes: addr=%s, message=%s", base_addr, e.getMessage()));
				break;
			}
		}

		if(datatype_holder.get_datatype_map().size()==0)
		{
			return false;
		}
		return true;
	}

	private boolean analyze_type(Address type_base_addr, long offset, boolean is_go16) throws InvalidBinaryStructureException {
		if(datatype_holder.contain_key(offset)) {
			return true;
		}

		GolangDatatype go_datatype=GolangDatatype.create_by_parsing(go_bin, type_base_addr, offset, is_go16);
		datatype_holder.put_datatype(offset, go_datatype);

		for(long dependence_type_key : go_datatype.get_dependence_type_key_list()) {
			try {
				analyze_type(type_base_addr, dependence_type_key, is_go16);
			} catch(InvalidBinaryStructureException e) {
				Logger.append_message(String.format("Failed to analyze dependence type: addr=%s, offset=%x, message=%s", type_base_addr, offset, e.getMessage()));
			}
		}
		go_datatype.make_datatype(datatype_holder);
		datatype_holder.replace_datatype(offset, go_datatype);

		return true;
	}
}
