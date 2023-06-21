package golanganalyzerextension.gobinary;

import ghidra.program.model.data.AbstractUnsignedIntegerDataType;
import ghidra.program.model.data.DataTypeManager;

public class UnsignedInteger4DataType extends AbstractUnsignedIntegerDataType {

	/** A statically defined UnsignedInteger4DataType instance.*/
	public final static UnsignedInteger4DataType dataType = new UnsignedInteger4DataType();

	public UnsignedInteger4DataType() {
		this(null);
	}

	public UnsignedInteger4DataType(DataTypeManager dtm) {
		super("uint4", dtm);
	}

	@Override
	public String getDescription() {
		return "Unsigned 4-Byte Integer";
	}

	@Override
	public int getLength() {
		return 4;
	}

	@Override
	public Integer4DataType getOppositeSignednessDataType() {
		return Integer4DataType.dataType.clone(getDataTypeManager());
	}

	@Override
	public UnsignedInteger4DataType clone(DataTypeManager dtm) {
		if (dtm == getDataTypeManager()) {
			return this;
		}
		return new UnsignedInteger4DataType(dtm);
	}
}
