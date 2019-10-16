package ch.krmpoti.master;

import java.util.List;
import java.util.Map;

public class TimeBasedBFESecretKey {

    private Filter filter;
    private Map<Integer, Triple<ECPoint, ECPoint, List<ECPoint>>> bloomSecretKey;
    private Map<String, Triple<ECPoint, ECPoint, List<ECPoint>>> timeSecretKey;
    private String timeIntervalId;

    public TimeBasedBFESecretKey(Filter filter, Map bloomSecretKey, Map timeSecretKey, String timeIntervalId) {
        this.filter = filter;
        this.bloomSecretKey = bloomSecretKey;
        this.timeSecretKey = timeSecretKey;
        this.timeIntervalId = timeIntervalId;
    }

    public Filter getFilter() {
        return filter;
    }

    public void setFilter(Filter filter) {
        this.filter = filter;
    }

    public Map<Integer, Triple<ECPoint, ECPoint, List<ECPoint>>> getBloomSecretKey() {
        return bloomSecretKey;
    }

    public void setBloomSecretKey(Map<Integer, Triple<ECPoint, ECPoint, List<ECPoint>>> bloomSecretKey) {
        this.bloomSecretKey = bloomSecretKey;
    }

    public Map<String, Triple<ECPoint, ECPoint, List<ECPoint>>> getTimeSecretKey() {
        return timeSecretKey;
    }

    public void setTimeSecretKey(Map<String, Triple<ECPoint, ECPoint, List<ECPoint>>> timeSecretKey) {
        this.timeSecretKey = timeSecretKey;
    }

    public String getTimeIntervalId() {
        return timeIntervalId;
    }

    public void setTimeIntervalId(String timeIntervalId) {
        this.timeIntervalId = timeIntervalId;
    }
}
