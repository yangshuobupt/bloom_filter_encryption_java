package ch.krmpoti.master;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.logging.Level;
import java.util.logging.Logger;

public class BloomFilterEncryption {

    private static final Logger LOGGER = Logger.getLogger(BloomFilterEncryption.class.getName());
    private static final int IBE_SECURITY_PARAM = 382;

    public static Pair<BFESystemParams, BFESecretKey> generateKeys(int k, int
            filterElementNumber, double filterFalsePositiveProbability) {
        LOGGER.log(Level.INFO, "Generating keys for the Bloom Filter Encryption with bloom filter with expected n = " +
                "{0} and false positive probability of {1}.",
                new Object[]{filterElementNumber, filterFalsePositiveProbability});
        Filter filter = new BloomFilter(filterElementNumber, filterFalsePositiveProbability);

        Pair<IBESystemParams, BigInteger> ibeSystemParamsWithMasterKey = BonehFranklinIBE.setup
                (IBE_SECURITY_PARAM);

        BFESystemParams bfeSystemParams = new BFESystemParamsImpl(k, filter.size(), filter.getHashCount(),
                ibeSystemParamsWithMasterKey.getFirstElement());

        List<ECPoint> secretKey = new ArrayList<>(filter.size());

        for (int i = 0; i < filter.size(); i++) {
            secretKey.add(i, BonehFranklinIBE.extract(
                    ibeSystemParamsWithMasterKey.getFirstElement(),
                    ibeSystemParamsWithMasterKey.getSecondElement(),
                    Utils.convertIntToBytes(i))
            );
        }

        BFESecretKey bfeSecretKey = new BFESecretKey(filter, secretKey);
        return new Pair<>(bfeSystemParams, bfeSecretKey);
    }

    public static Pair<BFECiphertext, byte[]> encrypt(BFESystemParams bfeSystemParams, BigInteger r, byte[] K) {
        IBESystemParams ibeSystemParams = bfeSystemParams.getIBESystemParams();

        int keyLength = bfeSystemParams.getSecurityParameter();

        int[] bitPositions = BloomFilter.getBitPositions(ibeSystemParams.getGroup1Generator().multiplyPoint(r),
                bfeSystemParams.getFilterHashCount(), bfeSystemParams.getFilterSize());

        byte[][] ciphertexts = new byte[bitPositions.length][keyLength];
        Pair<ECPoint, byte[]> tempCiphertext = null;
        for (int i = 0; i < bitPositions.length; i++) {
            tempCiphertext = BonehFranklinIBE.encrypt(ibeSystemParams, Utils.convertIntToBytes(bitPositions[i]), K, r);
            ciphertexts[i] = tempCiphertext.getSecondElement();
        }

        BFECiphertext bfeCiphertext = new BFECiphertext(tempCiphertext.getFirstElement(), ciphertexts);
        return new Pair<>(bfeCiphertext, K);
    }

    public static Pair<BFECiphertext, byte[]> encrypt(BFESystemParams bfeSystemParams) {
//        LOGGER.log(Level.INFO, "Encrypting the random generated key.");
        SecureRandom random = new SecureRandom();
        IBESystemParams ibeSystemParams = bfeSystemParams.getIBESystemParams();

        int keyLength = bfeSystemParams.getSecurityParameter();
        byte[] K = new byte[keyLength];
        random.nextBytes(K);

        Pair<BigInteger, byte[]> exponentAndKeyPrime = generateExponentAndKeyPrime(K,
                bfeSystemParams.getIBESystemParams().getOrder().bitLength() / Byte.SIZE,
                bfeSystemParams.getSecurityParameter() / Byte.SIZE);
        BigInteger r = exponentAndKeyPrime.getFirstElement();
        byte[] Kprime = exponentAndKeyPrime.getSecondElement();

        int[] bitPositions = BloomFilter.getBitPositions(ibeSystemParams.getGroup1Generator().multiplyPoint(r),
                bfeSystemParams.getFilterHashCount(), bfeSystemParams.getFilterSize());

        byte[][] ciphertexts = new byte[bitPositions.length][keyLength];
        Pair<ECPoint, byte[]> tempCiphertext = null;
        for (int i = 0; i < bitPositions.length; i++) {
            tempCiphertext = BonehFranklinIBE.encrypt(ibeSystemParams, Utils.convertIntToBytes(bitPositions[i]), K, r);
            ciphertexts[i] = tempCiphertext.getSecondElement();
        }

        BFECiphertext bfeCiphertext = new BFECiphertext(tempCiphertext.getFirstElement(), ciphertexts);
        return new Pair<>(bfeCiphertext, Kprime);
    }

    // note in docu this method runs in place
    public static BFESecretKey puncture(BFESecretKey secretKey, BFECiphertext cipherText) {
        int[] affectedIndexes = secretKey.getFilter().add(cipherText.getFirstElement());
        for (int affectedIndex : affectedIndexes) {
            secretKey.getSecretKey().set(affectedIndex, null);
        }

//        LOGGER.log(Level.INFO, "The key has been punctured.");
        return secretKey;
    }

    public static byte[] decrypt(BFESystemParams bfeSystemParams, BFESecretKey secretKey,
                                 BFECiphertext cipherText) throws KeyAlreadyPuncturedException {
//        LOGGER.log(Level.INFO, "Decrypting the secret key.");
        if (secretKey.getFilter().maybeContains(cipherText.getFirstElement())) {
            throw new KeyAlreadyPuncturedException("Secret key already punctured with the given ciphertext!");
        }
        IBESystemParams ibeSystemParams = bfeSystemParams.getIBESystemParams();

        int[] affectedIndexes = BloomFilter.getBitPositions(cipherText.getFirstElement(), bfeSystemParams.getFilterHashCount(),
                bfeSystemParams.getFilterSize());

        byte[] K = new byte[20];
        for (int i = 0; i < affectedIndexes.length; i++) {
            if (secretKey.getSecretKey().get(affectedIndexes[i]) != null) {
                Pair<ECPoint, byte[]> IBECiphertext = new Pair<>(cipherText.getFirstElement(), cipherText.getSecondElement()[i]);
                K = BonehFranklinIBE.decrypt(ibeSystemParams, IBECiphertext, secretKey.getSecretKey()
                        .get(affectedIndexes[i]));
                break;
            }
        }


        Pair<BigInteger, byte[]> exponentAndKeyPrime = generateExponentAndKeyPrime(K,
                bfeSystemParams.getIBESystemParams().getOrder().bitLength() / Byte.SIZE,
                bfeSystemParams.getSecurityParameter() / Byte.SIZE);

        BigInteger r = exponentAndKeyPrime.getFirstElement();
        Pair<BFECiphertext, byte[]> cK = encrypt(bfeSystemParams, r, K);

        // TODO refactor this
        if (Arrays.deepEquals(cK.getFirstElement().getSecondElement(), cipherText.getSecondElement()) &&
                cK.getFirstElement().getFirstElement().getPoint().equals(cipherText.getFirstElement().getPoint())) {
            //LOGGER.log(Level.INFO, "Secret key successfully decrypted.");
            return K;
        }

        return null;
    }

    private static Pair<BigInteger, byte[]> generateExponentAndKeyPrime(byte[] K, int exponentLength, int keyLength) {
        int totalDigestLength = keyLength + exponentLength;
        byte[] shakeDigest = Utils.getSHAKE256digest(K, totalDigestLength);
        byte[] exponentDigest = Arrays.copyOfRange(shakeDigest, 0, exponentLength);
        byte[] Kprime = Arrays.copyOfRange(shakeDigest, exponentLength, totalDigestLength);

        BigInteger exponent = new BigInteger(1, exponentDigest);

        return new Pair<>(exponent, Kprime);
    }

}
