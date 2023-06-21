package golanganalyzerextension.gobinary;

import ghidra.program.model.data.AbstractSignedIntegerDataType;
import ghidra.program.model.data.DataOrganization;
import ghidra.program.model.data.DataTypeManager;

public class Integer4DataType extends AbstractSignedIntegerDataType {

	/** A statically defined Integer4DataType instance.*/
	public final static Integer4DataType dataType = new Integer4DataType();

	public Integer4DataType() {
		this(null);
	}

	public Integer4DataType(DataTypeManager dtm) {
		super("int4", dtm);
	}

	@Override
	public String getDescription() {
		return "Signed 4-Byte Integer";
	}

	@Override
	public int getLength() {
		return 4;
	}

	@Override
	public UnsignedInteger4DataType getOppositeSignednessDataType() {
		return UnsignedInteger4DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public Integer4DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new Integer4DataType(dtm);
	}

	@Override
	public String getCTypeDeclaration(DataOrganization dataOrganization) {
		return getCTypeDeclaration(this, true, dataOrganization, false);
	}
}
