package ch.krmpoti.master;

import java.util.List;

public class BFESecretKey {

    private Filter filter;
    private List<ECPoint> secretKey;

    public BFESecretKey(Filter filter, List<ECPoint> secretKey) {
        this.filter = filter;
        this.secretKey = secretKey;
    }

    public Filter getFilter() {
        return filter;
    }

    public void setFilter(Filter filter) {
        this.filter = filter;
    }

    public List<ECPoint> getSecretKey() {
        return secretKey;
    }

    public void setSecretKey(List<ECPoint> secretKey) {
        this.secretKey = secretKey;
    }
}
