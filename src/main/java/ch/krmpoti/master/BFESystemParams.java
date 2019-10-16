package ch.krmpoti.master;

public abstract class BFESystemParams {

    protected int securityParameter;
    protected int filterSize;
    protected int filterHashCount;
    protected IBESystemParams ibeSystemParams;
    protected int timeSlotsQuantityExponent = 1;

    public BFESystemParams(int securityParameter, int filterSize, int filterHashCount, IBESystemParams ibeSystemParams) {
        this.securityParameter = securityParameter;
        this.filterSize = filterSize;
        this.filterHashCount = filterHashCount;
        this.ibeSystemParams = ibeSystemParams;
    }

    abstract void setSecurityParameter(int securityParameter);
    abstract int getSecurityParameter();

    abstract void setFilterSize(int filterSize);
    abstract int getFilterSize();

    abstract void setFilterHashCount(int filterHashCount);
    abstract int getFilterHashCount();

    abstract void setIBESystemParams(IBESystemParams ibeSystemParams);
    abstract IBESystemParams getIBESystemParams();

    abstract void setTimeSlotsQuantityExponent(int quantityExponent);
    abstract int getTimeSlotsQuantityExponent();

}
