package ch.krmpoti.master;

import iaik.security.md.SHAKE256InputStream;

import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.security.SecureRandom;
import java.util.Arrays;

public class Utils {

    /**
     * Generates a secure random BigInteger from the open range between the zero and the given parameter.
     *
     * @param exclusiveUpperBound The upper bound of the possible random number, excluded.
     * @return Secure random BigInteger
     */
    public static BigInteger generateRandomPositiveBigInteger(BigInteger exclusiveUpperBound) {
        SecureRandom random = new SecureRandom();
        BigInteger result;

        do {
            result = new BigInteger(exclusiveUpperBound.bitLength(), random);
        } while (result.compareTo(BigInteger.ZERO) == 0 || result.compareTo(exclusiveUpperBound) >= 0);

        return result;
    }

    /**
     * Generates a secure random BigInteger of maximum bit length bitLen.
     *
     * @param bitLen Maximum length of generated value.
     * @return Secure random BigInteger
     */
    public static BigInteger generateRandomBigInteger(int bitLen) {
        SecureRandom random = new SecureRandom();
        return new BigInteger(bitLen, random);
    }

    /**
     * XOR operation on two byte arrays.
     *
     * @param array1 The first byte array.
     * @param array2 The second byte array.
     * @return The result of XOR operation on the two given byte arrays.
     */
    public static byte[] byteArraysXOR(byte[] array1, byte[] array2) {
        // add padding to the smaller array
        if (array1.length != array2.length) {
            if (array1.length < array2.length) {
                array1 = Arrays.copyOf(array1, array2.length);
            } else {
                array2 = Arrays.copyOf(array2, array1.length);
            }
        }

        byte[] result = new byte[array1.length];
        for (int i = 0; i < array1.length; i++) {
            result[i] = (byte) (array1[i] ^ array2[i]);
        }

        return result;
    }

    /**
     * Converts a given integer to bytes in big endian order.
     *
     * @param value The integer to be converted.
     * @return A byte array.
     */
    public static byte[] convertIntToBytes(int value) {
        ByteBuffer buffer = ByteBuffer.allocate(Integer.BYTES);
        buffer.order(ByteOrder.BIG_ENDIAN);

        return buffer.putInt(value).array();
    }

    /**
     * Outputs a SHAKE256 digest of a given byte array.
     *
     * @param a The input byte array.
     * @param outputSize The target output size of the digest in bytes.
     * @return A SHAKE256 digest of the given length.
     */
    public static byte[] getSHAKE256digest(byte[] a, int outputSize) {
        SHAKE256InputStream shake256In = new SHAKE256InputStream(outputSize);

        shake256In.update(a);
        byte[] digest = new byte[outputSize];
        try {
            shake256In.read(digest);
            shake256In.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        return digest;
    }

    /**
     * Outputs a 0-padded string to given length. If source string is bigger or the same as target length the
     * original string will be returned without any change.
     *
     * @param a The string to be padded.
     * @param targetLength The target length to which the string will be padded.
     * @return String of defined length padded with zeros.
     */
    public static String padStringWithZeros(String a, int targetLength) {
        if (a.length() >= targetLength) {
            return a;
        }
        return String.format("%" + targetLength + "s", a).replace(" ", "0");
    }

    /**
     * Calculates base 2 logarithm of a given number.
     *
     * @param number The number of which the logarithm is to be calculated.
     * @return Base 2 logarithm.
     */
    public static double log2(int number) {
        return Math.log(number) / Math.log(2);
    }

    /**
     * Compares two given binary numbers.
     *
     * @param a The first binary string.
     * @param b The second binary string.
     * @return 0 if numbers are equal, -1 if a < b, 1 if a > b
     */
    public static int compareBinaryStrings(String a, String b) {
        if (a.length() > b.length()) {
            b = padStringWithZeros(b, a.length());
        } else {
            a = padStringWithZeros(a, b.length());
        }
        return a.compareTo(b);
    }

    /**
     * Increments a binary number
     *
     * @param a The binary string.
     * @return Binary number as a String incremented by one. The result is padded to be at least the same length as
     * the original one.
     */
    public static String incrementBinaryString(String a) {
        int numericalValue = Integer.parseInt(a, 2);
        numericalValue++;
        return padStringWithZeros(Integer.toBinaryString(numericalValue), a.length());
    }
}
