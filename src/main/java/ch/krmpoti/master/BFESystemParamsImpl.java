package ch.krmpoti.master;

public class BFESystemParamsImpl extends BFESystemParams {

    public BFESystemParamsImpl(int securityParameter, int filterSize, int filterHashCount, IBESystemParams ibeSystemParams) {
        super(securityParameter, filterSize, filterHashCount, ibeSystemParams);
    }

    @Override
    public void setSecurityParameter(int securityParameter) {
        this.securityParameter = securityParameter;
    }

    @Override
    public int getSecurityParameter() {
        return securityParameter;
    }

    @Override
    public void setFilterSize(int filterSize) {
        this.filterSize = filterSize;
    }

    @Override
    public int getFilterSize() {
        return filterSize;
    }

    @Override
    public void setFilterHashCount(int filterHashCount) {
        this.filterHashCount = filterHashCount;
    }

    @Override
    public int getFilterHashCount() {
        return filterHashCount;
    }

    @Override
    public void setIBESystemParams(IBESystemParams ibeSystemParams) {
        this.ibeSystemParams = ibeSystemParams;
    }

    @Override
    public IBESystemParams getIBESystemParams() {
        return ibeSystemParams;
    }

    @Override
    public void setTimeSlotsQuantityExponent(int quantityExponent) {
        this.timeSlotsQuantityExponent = quantityExponent;
    }

    @Override
    public int getTimeSlotsQuantityExponent() {
        return timeSlotsQuantityExponent;
    }
}
