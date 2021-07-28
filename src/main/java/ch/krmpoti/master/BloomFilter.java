package ch.krmpoti.master;

import java.util.BitSet;
import java.util.logging.Level;
import java.util.logging.Logger;

public class BloomFilter implements Filter {

    private static final Logger LOGGER = Logger.getLogger(BloomFilter.class.getName());
    private static final int HASH_SEED_1 = 657635;
    private static final int HASH_SEED_2 = 423646; // TODO maybe random in constructor?

    private int hashCount;
    private int size;
    private BitSet bitSet;
    private int storedElementsCount;

    public BloomFilter(int size, int hashCount) {
        if (size < 1) {
            throw new IllegalArgumentException("Provided bloom filter size has to be a positive integer!");
        }

        this.size = size;
        this.hashCount = hashCount;
        this.bitSet = new BitSet(size);
        this.storedElementsCount = 0;

        LOGGER.log(Level.INFO, "Instantiated Bloom Filter (size: " + size + " bits, hash count: " +
                hashCount + ").");
    }

    //
    public BloomFilter(int n, double falsePositiveProbability) {
        if (n < 1) {
            throw new IllegalArgumentException("Provided bloom filter element number has to be a positive integer!");
        }
        if (falsePositiveProbability <= 0) {
            throw new IllegalArgumentException("Provided false positive probability has to be a positive number!");
        }

        this.size = (int) - Math.floor((n * Math.log(falsePositiveProbability)) / Math.pow(Math.log(2), 2));
        this.hashCount = (int) Math.round((size / (double) n) * Math.log(2));
        this.bitSet = new BitSet(size);
        this.storedElementsCount = 0;

        LOGGER.log(Level.INFO, "Instantiated Bloom Filter (size: " + size + " bits, hash count: " +
                hashCount + ").");
    }

    @Override
    public int size() {
        return size;
    }

    @Override
    public int getHashCount() {
        return hashCount;
    }

    @Override
    public int[] add(Object a) {
        int[] bitPositions = getBitPositions(a, hashCount, size);

        for (int bitPosition : bitPositions) {
            this.bitSet.set(bitPosition);
        }

        this.storedElementsCount++;
        LOGGER.log(Level.FINE, "Element added to the bloom filter. False positive probability is now " +
                getCurrentFalsePositiveProbability());

        return bitPositions;
    }

    @Override
    public boolean maybeContains(Object a) {
        int[] bitPositions = getBitPositions(a, hashCount, size);
        boolean contains = true;

        for (int bitPosition : bitPositions) {
            contains &= this.bitSet.get(bitPosition);
        }

        return contains;
    }

    @Override
    public void reset() {
        this.bitSet.clear();
        this.storedElementsCount = 0;
    }

    public double getCurrentFalsePositiveProbability() {
        return Math.pow(1 - Math.exp((-1 * hashCount * this.storedElementsCount) / (double) size), hashCount);
    }

    public static int[] getBitPositions(Object a, int hashCount, int filterSize) {
        int[] bitPositions = new int[hashCount];

        for (int i = 0; i < bitPositions.length; i++) {
            bitPositions[i] = Math.abs(
                    MurmurHash3.murmurhash3_x86_32(Utils.convertIntToBytes(a.hashCode()), 0, Integer.BYTES, HASH_SEED_1)
                            + i * MurmurHash3.murmurhash3_x86_32(Utils.convertIntToBytes(a.hashCode()), 0, Integer
                            .BYTES, HASH_SEED_2)) % filterSize;
        }


        return bitPositions;
    }

}
