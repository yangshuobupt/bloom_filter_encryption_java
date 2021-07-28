import ch.krmpoti.master.*;
import com.opencsv.CSVWriter;
import iaik.security.ec.math.curve.AtePairingOverBarretoNaehrigCurveFactory;
import iaik.security.ec.math.curve.PairingTypes;
import iaik.security.ec.provider.ECCelerate;
import iaik.security.provider.IAIK;
import org.apache.commons.lang3.time.StopWatch;

import java.io.FileWriter;
import java.io.IOException;
import java.math.BigInteger;
import java.security.Security;
import java.util.List;
import java.util.Objects;
import java.util.Random;
import java.util.logging.Level;
import java.util.logging.Logger;

public class Main {

    // TODO remove or clean this up
    private static final Logger LOGGER = Logger.getLogger(Main.class.getName());


    public static void main(String[] args) {
        IAIK.addAsProvider();
        Security.addProvider(new ECCelerate(true));

//        if ("basic".equalsIgnoreCase(args[0])) {
//            testBasicBloomEncryption(Integer.parseInt(args[1]), Integer.parseInt(args[2]));
//        } else if ("basic-start".equalsIgnoreCase(args[0])) {
//            writeBasicBFHeaders();
//            testBasicBloomEncryption(Integer.parseInt(args[1]), Integer.parseInt(args[2]));
//        } else if ("tb-start".equalsIgnoreCase(args[0])){
//            writeTimeBasedBFHeaders();
//            testTimeBasedBFE(Integer.parseInt(args[1]), Integer.parseInt(args[2]), Integer.parseInt(args[3]), args[4]);
//        } else if ("tb".equalsIgnoreCase(args[0])){
//            testTimeBasedBFE(Integer.parseInt(args[1]), Integer.parseInt(args[2]), Integer.parseInt(args[3]), args[4]);
//        } else if ("functions".equalsIgnoreCase(args[0])) {
//            writeFunctionsHeaders();
//            for (int i = 0; i < 500; i++) {
//                testFunctions();
//            }
//        }
        //testBasicBloomEncryption();
        testTimeBasedBFE(8,12,1,"000000000001");

    }

    public static void testBasicBloomEncryption() {

        Pair<BFESystemParams, BFESecretKey> bloomFilterEncryptionSecretKey =
                BloomFilterEncryption.generateKeys(128, 100, 0.001);

        Pair<BFECiphertext, byte[]> ciphertext = null;



        for (int i = 0; i< 5; i++) {
            ciphertext = BloomFilterEncryption.encrypt(bloomFilterEncryptionSecretKey.getFirstElement());

            try {
                System.out.println("KEY2: " + new String(Objects.requireNonNull(BloomFilterEncryption.decrypt
                        (bloomFilterEncryptionSecretKey.getFirstElement(),
                                bloomFilterEncryptionSecretKey.getSecondElement(),
                                ciphertext.getFirstElement()))));
            } catch (KeyAlreadyPuncturedException e) {
                e.printStackTrace();
            }

            BloomFilterEncryption.puncture(bloomFilterEncryptionSecretKey.getSecondElement(), ciphertext.getFirstElement());
        }


    }

    public static void ctestBasicBloomEncryption(int filterElementNumber, int encryptionsNum) {
        LOGGER.log(Level.INFO, "-------------------- TEST START ------------------------");
        StopWatch timerKeyGen = new StopWatch();
        StopWatch timerEnc = new StopWatch();
        StopWatch timerDec = new StopWatch();
        StopWatch timerPunc = new StopWatch();
        int exceptions = 0;

        timerKeyGen.start();
        Pair<BFESystemParams, BFESecretKey> bloomFilterEncryptionSecretKey =
                BloomFilterEncryption.generateKeys(128, filterElementNumber, 0.001);
        timerKeyGen.stop();

        Pair<BFECiphertext, byte[]> ciphertext = null;

        timerEnc.start();
        timerEnc.suspend();
        timerDec.start();
        timerDec.suspend();
        timerPunc.start();
        timerPunc.suspend();

        for (int i = 0; i< encryptionsNum; i++) {
            timerEnc.resume();
            ciphertext = BloomFilterEncryption.encrypt(bloomFilterEncryptionSecretKey.getFirstElement());
            timerEnc.suspend();
            timerDec.resume();
            try {
                BloomFilterEncryption.decrypt(bloomFilterEncryptionSecretKey.getFirstElement(),
                        bloomFilterEncryptionSecretKey.getSecondElement(),
                        ciphertext.getFirstElement());
            } catch (KeyAlreadyPuncturedException e) {
                exceptions++;
                e.printStackTrace();
            }
            timerDec.suspend();
            timerPunc.resume();
            BloomFilterEncryption.puncture(bloomFilterEncryptionSecretKey.getSecondElement(), ciphertext.getFirstElement());
            timerPunc.suspend();
        }
        timerEnc.stop();
        timerDec.stop();
        timerPunc.stop();

        try {
            CSVWriter csvWriter = new CSVWriter(new FileWriter("basic_bfe.csv", true));
            csvWriter.writeNext(new String[]{
                    Integer.toString(filterElementNumber),
                    Integer.toString(encryptionsNum),
                    Double.toString(1.0 * timerKeyGen.getNanoTime() / 1000000),
                    Double.toString(1.0 * timerEnc.getNanoTime() / encryptionsNum / 1000000),
                    Double.toString(1.0 * timerDec.getNanoTime() / encryptionsNum / 1000000),
                    Double.toString(1.0 * timerPunc.getNanoTime() / encryptionsNum),
                    Integer.toString(exceptions)});
            csvWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        LOGGER.log(Level.INFO, "-------------------- TEST END ------------------------");
    }

    public static void testHIBE() {
        Pair<IBESystemParams, ECPoint> test1 = HierarchicalIBE.setup(7, 382);

        String testBitset = "1001";

        Triple<ECPoint, ECPoint, List<ECPoint>> test2 = HierarchicalIBE.extract(test1.getFirstElement(), test1.getSecondElement(),
                testBitset);

        String testBitset2 = "10010";

        Triple<ECPoint, ECPoint, List<ECPoint>> test3 = HierarchicalIBE.derive(test1.getFirstElement(), test2,
                testBitset2);

        Triple<ECPoint, ECPoint, List<ECPoint>> test4 = HierarchicalIBE.extract(test1.getFirstElement(),
                test1.getSecondElement(),
                testBitset2);

        Triple<ExtensionFieldElement, ECPoint, ECPoint> ciphertext = HierarchicalIBE.encrypt
                (test1.getFirstElement(), testBitset2, "marin".getBytes());

        System.out.println("decrypted: " + new String(HierarchicalIBE.decrypt(test1.getFirstElement(), ciphertext,
                test3)).trim());

        System.out.println("decrypted: " + new String(HierarchicalIBE.decrypt(test1.getFirstElement(), ciphertext,
                test4)).trim());

        System.out.println("BREAKPOINT HERE");
    }

    public static void testTimeBasedBFE(int filterElementNumber, int timeSlotsExponent, int encryptionsNum, String
            timeSlot) {
        LOGGER.log(Level.INFO, "-------------------- TEST START ------------------------");
        StopWatch timerEnc = new StopWatch();
        StopWatch timerDec = new StopWatch();
        StopWatch timerPunc = new StopWatch();
        int exceptions = 0;

        double intervalNum = Math.pow(2, timeSlotsExponent);

        Pair<Pair<Long, Long>, Pair<BFESystemParams, TimeBasedBFESecretKey>> bloomFilterEncryptionSecretKey =
                TimeBasedBloomFilterEncryption
                .generateKeys(128, filterElementNumber, 0.001, timeSlotsExponent);

        Long singleGenBloom = bloomFilterEncryptionSecretKey.getFirstElement().getFirstElement();
        Long totalGenTime = bloomFilterEncryptionSecretKey.getFirstElement().getSecondElement();

        Pair<List<Triple<byte[], ECPoint, ECPoint>>, byte[]> ciphertext = null;

        timerEnc.start();
        timerEnc.suspend();
        timerDec.start();
        timerDec.suspend();
        timerPunc.start();
        timerPunc.suspend();

        for (int i = 0; i < encryptionsNum; i++) {
            timerEnc.resume();
            ciphertext = TimeBasedBloomFilterEncryption.encrypt(bloomFilterEncryptionSecretKey.getSecondElement()
                            .getFirstElement(), timeSlot);
            timerEnc.suspend();
            timerDec.resume();
            try {
                TimeBasedBloomFilterEncryption
                        .decrypt(bloomFilterEncryptionSecretKey.getSecondElement().getFirstElement(),
                                bloomFilterEncryptionSecretKey.getSecondElement().getSecondElement(), ciphertext);
            } catch (KeyAlreadyPuncturedException e) {
                exceptions++;
                e.printStackTrace();
            }
            timerDec.suspend();
            timerPunc.resume();
            TimeBasedBloomFilterEncryption.punctureKey(bloomFilterEncryptionSecretKey.getSecondElement().getSecondElement(),
                    ciphertext);
            timerPunc.suspend();
        }
        timerEnc.stop();
        timerDec.stop();
        timerPunc.stop();
        Pair<Long, Long> puncturingTimes;

        for (int i = 1; i < intervalNum; i++) {
            try {
                puncturingTimes = TimeBasedBloomFilterEncryption.punctureInterval(bloomFilterEncryptionSecretKey.getSecondElement()
                                .getFirstElement(), bloomFilterEncryptionSecretKey.getSecondElement().getSecondElement());
                totalGenTime += puncturingTimes.getSecondElement();
            } catch (ParentKeyNotAvailableException e) {
                e.printStackTrace();
            }
        }

        try {
            CSVWriter csvWriter = new CSVWriter(new FileWriter("tb_bfe.csv", true));
            csvWriter.writeNext(new String[]{
                    Long.toString(Math.round(Utils.log2(filterElementNumber))),
                    Integer.toString(timeSlotsExponent),
                    Integer.toString(encryptionsNum),
                    Double.toString(1.0 * singleGenBloom / 1000000),
                    Double.toString(1.0 * totalGenTime / intervalNum / 1000000),
                    Double.toString(1.0 * timerEnc.getNanoTime() / encryptionsNum / 1000000),
                    Double.toString(1.0 * timerDec.getNanoTime() / encryptionsNum / 1000000),
                    Double.toString(1.0 * timerPunc.getNanoTime() / encryptionsNum),
                    Integer.toString(exceptions)});
            csvWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }

        LOGGER.log(Level.INFO, "-------------------- TEST END ------------------------");

    }

    public static void testFunctions() {
        StopWatch timerMulti1 = new StopWatch();
        StopWatch timerMulti2 = new StopWatch();
        StopWatch timerAdd1 = new StopWatch();
        StopWatch timerAdd2 = new StopWatch();
        StopWatch timerPair = new StopWatch();
        StopWatch timerExp = new StopWatch();
        StopWatch timerTargetMul = new StopWatch();

        iaik.security.ec.math.field.ExtensionFieldElement targetElement;

        iaik.security.ec.math.curve.Pairing pairing = AtePairingOverBarretoNaehrigCurveFactory.getPairing(PairingTypes.TYPE_3, 382);
        BigInteger prvi = new BigInteger("4726051800608071234447728720936177102065704700928250754388979184795129312007632807170550983091025633451829472146932");

        timerMulti1.start();
        iaik.security.ec.math.curve.ECPoint point1 = pairing.getGroup1().getGenerator().multiplyPoint(prvi);
        timerMulti1.stop();
        timerMulti2.start();
        iaik.security.ec.math.curve.ECPoint point2 = pairing.getGroup2().getGenerator().multiplyPoint(prvi);
        timerMulti2.stop();
        timerAdd1.start();
        pairing.getGroup1().getGenerator().addPoint(point1);
        timerAdd1.stop();
        timerAdd2.start();
        pairing.getGroup2().getGenerator().addPoint(point2);
        timerAdd2.stop();
        timerPair.start();
        iaik.security.ec.math.field.ExtensionFieldElement paired = pairing.pair(point1, point2);
        timerPair.stop();
        timerExp.start();
        targetElement = paired.exponentiate(prvi);
        timerExp.stop();
        timerTargetMul.start();
        paired.multiply(targetElement);
        timerTargetMul.stop();


        LOGGER.log(Level.INFO, "timerMulti1 = {0}, timerMulti2 = {1}, timerAdd1 = {2}, timerAdd2 = {3}, timerPair = " +
                        "{4}, timerExp = {5}, timerTargetMul = {6}",
                new Object[]{timerMulti1.getNanoTime(), timerMulti2.getNanoTime(), timerAdd1.getNanoTime(),
                        timerAdd2.getNanoTime(), timerPair.getNanoTime(), timerExp.getNanoTime(), timerTargetMul
                        .getNanoTime()});
        try {
            CSVWriter csvWriter = new CSVWriter(new FileWriter("functions.csv", true));
            csvWriter.writeNext(new String[]{
                    Double.toString(1.0 * timerMulti1.getNanoTime() / 1000000),
                    Double.toString(1.0 * timerMulti2.getNanoTime() / 1000000),
                    Double.toString(timerAdd1.getNanoTime()),
                    Double.toString(timerAdd2.getNanoTime()),
                    Double.toString(1.0 * timerPair.getNanoTime() / 1000000),
                    Double.toString(1.0 * timerExp.getNanoTime() / 1000000),
                    Double.toString(1.0 * timerTargetMul.getNanoTime() / 1000000)});
            csvWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void writeFunctionsHeaders() {
        CSVWriter csvWriter = null;
        try {
            csvWriter = new CSVWriter(new FileWriter("functions.csv"));
            String[] entries = {"multi1 (ms)", "multi2 (ms)", "add1 (ns)", "add2 (ns)", "pair (ms)", "exp (ms)",
                    "targetMul (ms)"};
            csvWriter.writeNext(entries);
            csvWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void writeBasicBFHeaders() {
        CSVWriter csvWriter = null;
        try {
            csvWriter = new CSVWriter(new FileWriter("basic_bfe.csv"));
            String[] entries = {"#keys", "#encryptions", "keygen time (ms)", "single encryption time (ms)",
                    "single decryption time (ms)", "single puncture time (ns)", "#exceptions"};
            csvWriter.writeNext(entries);
            csvWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static void writeTimeBasedBFHeaders() {
        CSVWriter csvWriter = null;
        try {
            csvWriter = new CSVWriter(new FileWriter("tb_bfe.csv"));
            String[] entries = {"BF tree exponent", "time tree exponent", "#encryptions",
                    "single BF tree keygen time (ms)", "single time tree keygen time (ms)",
                    "single encryption time (ms)", "single decryption time (ms)", "single puncture time (ns)",
                    "#exceptions"};
            csvWriter.writeNext(entries);
            csvWriter.close();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

}