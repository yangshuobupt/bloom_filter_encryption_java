package ch.krmpoti.master;

import org.apache.commons.lang3.time.StopWatch;

import java.math.BigInteger;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.logging.Level;
import java.util.logging.Logger;

public class TimeBasedBloomFilterEncryption {

    private static final Logger LOGGER = Logger.getLogger(TimeBasedBloomFilterEncryption.class.getName());
    private static final int IBE_SECURITY_PARAM = 382;


    public static Pair<Pair<Long, Long>, Pair<BFESystemParams, TimeBasedBFESecretKey>> generateKeys(int k, int
            filterElementNumber, double filterFalsePositiveProbability, int timeSlotsExponent) {
        LOGGER.log(Level.INFO, "Generating keys for the Time-Based Bloom Filter Encryption with 2^{0} time-slots and" +
                        " bloom filter with expected n = {1} and false positive probability of {2}.",
                new Object[]{timeSlotsExponent, filterElementNumber, filterFalsePositiveProbability});
        //LOGGER.setLevel(Level.OFF);

        Filter filter = new BloomFilter(filterElementNumber, filterFalsePositiveProbability);
        int bloomFilterTreeDepth = calculateTargetBloomFilterTreeDepth(filter.size());

        Pair<IBESystemParams, ECPoint> ibeSystemParamsWithMasterKey = HierarchicalIBE.setup
                (timeSlotsExponent + bloomFilterTreeDepth, IBE_SECURITY_PARAM);

        BFESystemParams bfeSystemParams = new BFESystemParamsImpl(k, filter.size(), filter.getHashCount(),
                ibeSystemParamsWithMasterKey.getFirstElement());
        bfeSystemParams.setTimeSlotsQuantityExponent(timeSlotsExponent);

        Map<Integer, Triple<ECPoint, ECPoint, List<ECPoint>>> bloomSecretKey = new HashMap<>();
        Map<String, Triple<ECPoint, ECPoint, List<ECPoint>>> timeBasedSecretKey = new HashMap<>();


        timeBasedSecretKey.put("0",
                HierarchicalIBE.extract(ibeSystemParamsWithMasterKey.getFirstElement(),
                        ibeSystemParamsWithMasterKey.getSecondElement(), "0"));
        timeBasedSecretKey.put("1",
                HierarchicalIBE.extract(ibeSystemParamsWithMasterKey.getFirstElement(),
                        ibeSystemParamsWithMasterKey.getSecondElement(), "1"));
        ibeSystemParamsWithMasterKey.setSecondElement(null); // Destroy master key after the first two nodes are created

        String startNodeId = Utils.padStringWithZeros("", timeSlotsExponent);
        TimeBasedBFESecretKey bfeSecretKey = new TimeBasedBFESecretKey(filter, bloomSecretKey, timeBasedSecretKey,
                startNodeId);
        Pair<Long, Long> times = null;
        try {
            times = punctureInterval(bfeSystemParams, bfeSecretKey, startNodeId, true);
        } catch (ParentKeyNotAvailableException e) {
            e.printStackTrace();
        }

        return new Pair<>(times, new Pair<>(bfeSystemParams, bfeSecretKey));
    }

    public static Pair<List<Triple<byte[], ECPoint, ECPoint>>, byte[]> encrypt(BFESystemParams bfeSystemParams, String timeSlot) {
        IBESystemParams ibeSystemParams = bfeSystemParams.getIBESystemParams();

        int bloomFilterTreeDepth = calculateTargetBloomFilterTreeDepth(bfeSystemParams.getFilterSize());

        byte[] c = bfeSystemParams.getIBESystemParams()
                .getHashDigest(Utils.generateRandomPositiveBigInteger(ibeSystemParams.getOrder()).toByteArray(),
                        IBE_SECURITY_PARAM / Byte.SIZE);
        byte[] K = bfeSystemParams.getIBESystemParams()
                .getHashDigest(Utils.generateRandomPositiveBigInteger(ibeSystemParams.getOrder()).toByteArray(),
                        IBE_SECURITY_PARAM / Byte.SIZE); // TODO take the keylength from params?
        List<Triple<byte[], ECPoint, ECPoint>> encapsulatedKeys = new ArrayList<>(bfeSystemParams.getFilterHashCount());
        int[] bloomPositions = BloomFilter.getBitPositions(new BigInteger(c), bfeSystemParams.getFilterHashCount(),
                bfeSystemParams.getFilterSize());

        for (int bloomPosition : bloomPositions) {
            String keyIdentity = Integer.toBinaryString(bloomPosition);
            keyIdentity = timeSlot + Utils.padStringWithZeros(keyIdentity, bloomFilterTreeDepth);
            encapsulatedKeys.add(HIBKEMKeyEncapsulation.encapsulate(bfeSystemParams.getIBESystemParams(), keyIdentity, K));
        }

        return new Pair<>(encapsulatedKeys, c);
    }

    // note in docu this method runs in place
    public static TimeBasedBFESecretKey punctureKey(TimeBasedBFESecretKey secretKey, Pair<List<Triple<byte[], ECPoint, ECPoint>>, byte[]> cipherText) {
        //LOGGER.log(Level.INFO, "Starting puncturing of the key.");
        int[] affectedIndexes = secretKey.getFilter().add(new BigInteger(cipherText.getSecondElement()));
        for (int affectedIndex : affectedIndexes) {
            secretKey.getBloomSecretKey().remove(affectedIndex);
        }

        //LOGGER.log(Level.INFO, "The key has been punctured.");
        return secretKey;
    }

    // note in docu this method runs in place
    public static Pair<Long, Long> punctureInterval(BFESystemParams bfeSystemParams,
                                                    TimeBasedBFESecretKey secretKey, String intervalId,
                                                    boolean initial)
            throws ParentKeyNotAvailableException {
        LOGGER.log(Level.INFO, "Starting puncturing of the current time interval.");

        String closestTimeKeyId = intervalId;

        int timeBasedTreeDepth = bfeSystemParams.getTimeSlotsQuantityExponent();
        int bloomFilterTreeDepth = calculateTargetBloomFilterTreeDepth(bfeSystemParams.getFilterSize());

        // TODO postrozi mapove na tocne tipove svugdje
        while (!secretKey.getTimeSecretKey().containsKey(closestTimeKeyId)) {
            if (closestTimeKeyId.length() < 2) {
                throw new ParentKeyNotAvailableException("There is no higher-level key available that could be used " +
                        "for the generation of the target key. Time interval not punctured.");
            }
            closestTimeKeyId = closestTimeKeyId.substring(0, closestTimeKeyId.length() - 1);
        }

        secretKey.getFilter().reset();
        secretKey.getBloomSecretKey().clear(); // Destroy all the remaining keys.

        StopWatch timerGenTime = new StopWatch();
        StopWatch timerGenBloom = new StopWatch();

        timerGenTime.start();
        generateTimeBasedKeys(closestTimeKeyId, intervalId, secretKey.getTimeSecretKey().get(closestTimeKeyId),
                secretKey.getTimeSecretKey(), bfeSystemParams.getIBESystemParams());
        timerGenTime.stop();

        timerGenBloom.start();
        if (initial) {
            generateBloomFilterKeys(intervalId, secretKey.getTimeSecretKey().get(intervalId), timeBasedTreeDepth,
                    bloomFilterTreeDepth, secretKey.getFilter().size(), secretKey.getBloomSecretKey(),
                    bfeSystemParams.getIBESystemParams());
        }
        timerGenBloom.stop();

        secretKey.setTimeIntervalId(intervalId);
        secretKey.getTimeSecretKey().remove(intervalId);

        LOGGER.log(Level.INFO, "The time interval has been punctured. Interval is now: {0}", intervalId);
        return new Pair<>(timerGenBloom.getNanoTime(), timerGenTime.getNanoTime());
    }

    // note in docu this method runs in place
    public static Pair<Long, Long> punctureInterval(BFESystemParams bfeSystemParams,
                                                    TimeBasedBFESecretKey secretKey)
            throws ParentKeyNotAvailableException {
        String nextTimeIntervalId = Utils.incrementBinaryString(secretKey.getTimeIntervalId());
        return punctureInterval(bfeSystemParams, secretKey, nextTimeIntervalId, false);
    }

    public static byte[] decrypt(BFESystemParams bfeSystemParams, TimeBasedBFESecretKey secretKey,
                                 Pair<List<Triple<byte[], ECPoint, ECPoint>>, byte[]> cipherText) throws KeyAlreadyPuncturedException {
        //LOGGER.log(Level.INFO, "Decrypting the secret key.");
        if (secretKey.getFilter().maybeContains(new BigInteger(cipherText.getSecondElement()))) {
            throw new KeyAlreadyPuncturedException("Secret key already punctured with the given ciphertext!");
        }
        IBESystemParams ibeSystemParams = bfeSystemParams.getIBESystemParams();

        int[] affectedIndexes = BloomFilter.getBitPositions(new BigInteger(cipherText.getSecondElement()),
                bfeSystemParams.getFilterHashCount(), bfeSystemParams.getFilterSize());

        byte[] K;
        for (int i = 0; i < affectedIndexes.length; i++) {
            if (secretKey.getBloomSecretKey().get(affectedIndexes[i]) != null) {
                Triple<byte[], ECPoint, ECPoint> HIBECiphertext = cipherText.getFirstElement().get(i);
                K = HIBKEMKeyEncapsulation.expose(ibeSystemParams, HIBECiphertext,
                        secretKey.getBloomSecretKey().get(affectedIndexes[i]));
                //LOGGER.log(Level.INFO, "Secret key successfully decrypted.");
                return K;
            }
        }

        return null;
    }

    private static void generateBloomFilterKeys(String nodeId,
                                                Triple<ECPoint, ECPoint, List<ECPoint>> nodeKey,
                                                int timeBasedTreeDepth,
                                                int bloomFilterTreeDepth,
                                                int bloomFilterElementNumber,
                                                Map<Integer, Triple<ECPoint, ECPoint, List<ECPoint>>> secretKey,
                                                IBESystemParams systemParams) {
        String lastBloomIndexId = Integer.toBinaryString(bloomFilterElementNumber - 1)
                .substring(0, nodeId.length() - timeBasedTreeDepth);
        if (Utils.compareBinaryStrings(nodeId.substring(timeBasedTreeDepth), lastBloomIndexId) > 0) {
            return;
        }

        int fullTreeDepth = timeBasedTreeDepth + bloomFilterTreeDepth;

        if (nodeId.length() == fullTreeDepth) {
            int secretKeyIndex = Integer.parseInt(nodeId.substring(timeBasedTreeDepth), 2);
            secretKey.put(secretKeyIndex, nodeKey);
            return;
        }

        String leftNodeId = getLeftChildNodeId(nodeId);
        String rightNodeId = getRightChildNodeId(nodeId);
        //System.out.println(leftNodeId + "  " + rightNodeId);

        Triple<ECPoint, ECPoint, List<ECPoint>> leftNodeKey = HierarchicalIBE.derive(systemParams, nodeKey, leftNodeId);
        Triple<ECPoint, ECPoint, List<ECPoint>> rightNodeKey = HierarchicalIBE.derive(systemParams, nodeKey, rightNodeId);

        generateBloomFilterKeys(leftNodeId, leftNodeKey, timeBasedTreeDepth, bloomFilterTreeDepth,
                bloomFilterElementNumber, secretKey, systemParams);
        generateBloomFilterKeys(rightNodeId, rightNodeKey, timeBasedTreeDepth, bloomFilterTreeDepth,
                bloomFilterElementNumber, secretKey, systemParams);
    }

    private static void generateTimeBasedKeys(String currentNodeId,
                                              String targetNodeId,
                                              Triple<ECPoint, ECPoint, List<ECPoint>> currentNodeKey,
                                              Map<String, Triple<ECPoint, ECPoint, List<ECPoint>>> secretKey,
                                              IBESystemParams systemParams) {

        if (!currentNodeId.equals(targetNodeId.substring(0, currentNodeId.length())) || currentNodeId.equals(targetNodeId)) {
            return;
        }

        String leftNodeId = getLeftChildNodeId(currentNodeId);
        String rightNodeId = getRightChildNodeId(currentNodeId);

        Triple<ECPoint, ECPoint, List<ECPoint>> leftNodeKey = HierarchicalIBE.derive(systemParams, currentNodeKey,
                leftNodeId);
        Triple<ECPoint, ECPoint, List<ECPoint>> rightNodeKey = HierarchicalIBE.derive(systemParams, currentNodeKey,
                rightNodeId);

        secretKey.remove(currentNodeId); // Destroy key used on path
        secretKey.put(leftNodeId, leftNodeKey);
        secretKey.put(rightNodeId, rightNodeKey);

        generateTimeBasedKeys(leftNodeId, targetNodeId, leftNodeKey, secretKey, systemParams);
        generateTimeBasedKeys(rightNodeId, targetNodeId, rightNodeKey, secretKey, systemParams);
    }

    private static int calculateTargetBloomFilterTreeDepth(int filterSize) {
        return (int) Math.ceil(Utils.log2(filterSize));
    }

    private static int calculateTargetTimeBasedTreeDepth(int timeSlotsNumber) {
        return (int) Math.floor(Utils.log2(timeSlotsNumber));
    }

    private static int calculateNumberOfNodesOnLevel(int level) {
        return (int) Math.pow(2, level);
    }

    private static String getLeftChildNodeId(String parentNodeId) {
        return parentNodeId + "0";
    }

    private static String getRightChildNodeId(String parentNodeId) {
        return parentNodeId + "1";
    }

}
