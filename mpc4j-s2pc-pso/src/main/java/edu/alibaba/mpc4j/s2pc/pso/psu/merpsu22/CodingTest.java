package edu.alibaba.mpc4j.s2pc.pso.psu.merpsu22;

import com.google.common.base.Preconditions;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacket;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;
import edu.alibaba.mpc4j.crypto.phe.PheEngine;
import edu.alibaba.mpc4j.crypto.phe.PheFactory;
import edu.alibaba.mpc4j.crypto.phe.PheSecLevel;
import edu.alibaba.mpc4j.crypto.phe.impl.pai99.Pai99PhePublicKey;
import edu.alibaba.mpc4j.crypto.phe.params.*;

import edu.alibaba.mpc4j.common.rpc.pto.AbstractMultiPartyPto;
import org.apache.commons.lang3.time.StopWatch;



import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class CodingTest {
    public static BigInteger rawRerandomize(PhePublicKey pk, BigInteger ct, BigInteger r) {
        Preconditions.checkArgument(pk instanceof Pai99PhePublicKey);
        BigInteger modulus = pk.getModulus();
        BigInteger modulusSquared = pk.getCiphertextModulus();
        // 重随机化也使用DJN10优化方案，ct' = ct * r'^n mod n^2，其中r' ∈ Z_n
        return BigIntegerUtils.modPow(r, modulus, modulusSquared).multiply(ct).mod(modulusSquared);
    }

    public static BigInteger[] randomZn2(int num, BigInteger modulus, SecureRandom secureRandom) {
        assert num > 0;
        return IntStream.range(0, num)
                .mapToObj(index -> BigIntegerUtils.randomPositive(modulus.shiftRight(1), secureRandom))
                .toArray(BigInteger[]::new);
    }

    private static void pipelineReRand(PhePublicKey pk, BigInteger[] cts, BigInteger[] rs) {
        // 生成随机量
        // Pipeline过程，先执行整除倍，最后再循环一遍
        int serverElementSize = rs.length;
        int pipeSize = 256;
        boolean parallel = false;

        int pipelineTime = serverElementSize / pipeSize;
        int round;
        for (round = 0; round < pipelineTime; round++) {
            int offset = round * pipeSize;
            // 计算KEM
            IntStream intStream = IntStream.range(0, pipeSize);
            intStream = parallel ? intStream.parallel() : intStream;
            List<BigInteger> reRandCT = intStream
                    .mapToObj(index -> {
                        return rawRerandomize(pk, cts[offset + index], rs[offset + index]);
                    })
                    .collect(Collectors.toList());

        }
        int remain = serverElementSize - round * pipeSize;
        if (remain > 0) {
            int offset = round * pipeSize;
            // 计算KEM
            IntStream intStream = IntStream.range(0, remain);
            intStream = parallel ? intStream.parallel() : intStream;
            List<BigInteger> reRandCT = intStream
                    .mapToObj(index -> {
                        return rawRerandomize(pk, cts[offset + index], rs[offset + index]);
                    })
                    .collect(Collectors.toList());

        }
    }

    public static void testPai(){
        PheFactory.PheType pheType = PheFactory.PheType.PAI99;
        PheSecLevel pheSecLevel = PheSecLevel.LAMBDA_128;
        boolean signed = false;
        boolean parallel = false;


        int modulusBitLength = PheFactory.getModulusBitLength(pheType, pheSecLevel);
        PheKeyGenParams keyGenParams = new PheKeyGenParams(pheSecLevel, signed, modulusBitLength);

        byte[] seed = new byte[] { 0x00 };
        SecureRandom secureRandom = new SecureRandom(seed);
        /**
         * 半同态加密引擎
         */
        PheEngine pheEngine = PheFactory.createInstance(pheType, secureRandom);
        /**
         * 私钥
         */
        PhePrivateKey sk = pheEngine.keyGen(keyGenParams);

        PhePublicKey pk = sk.getPublicKey();

        long a, b, plainResult, decodedResult;

        PheCiphertext ciphertextA, encryptedResult;

        BigInteger rawCiphertextA, reRawCiphertextA;
        // 编码乘数、编码解密结果
        PhePlaintext encodedB, decryptedResult;

        a = secureRandom.nextInt() >> 1;
        b = secureRandom.nextInt() >> 1;
        if (!pk.isSigned()) {
            a = Math.abs(a);
            b = Math.abs(b);
        }
        plainResult = a * b;
        // 密文
        ciphertextA = pheEngine.encrypt(pk, a);
        // 编码
        encodedB = pk.encode(b);
        // 密文与明文运算
        encryptedResult = pheEngine.multiply(pk, ciphertextA, encodedB);
        decryptedResult = pheEngine.decrypt(sk, encryptedResult);
        decodedResult = decryptedResult.decodeLong();
        System.out.println(plainResult);
        System.out.println(decodedResult);

        BigInteger aa = BigInteger.valueOf(a);

        rawCiphertextA = pheEngine.rawEncrypt(pk, aa);

        BigInteger modulus = pk.getModulus();
        // FIXME Is the following secure? (Is the randomness picks from 0 to modulus - 1?)
        BigInteger r = BigIntegerUtils.randomPositive(modulus.shiftRight(1), secureRandom);

        reRawCiphertextA = rawRerandomize(pk, rawCiphertextA , r);
        BigInteger result = pheEngine.rawDecrypt(sk,reRawCiphertextA);

        int size = 1 << 10;
        System.out.println("test size: "+size);

        StopWatch stopWatch = new StopWatch();
        stopWatch.start();

        IntStream intStream = IntStream.range(0, size);
        intStream = parallel ? intStream.parallel() : intStream;
        BigInteger[] rawCiphertexts = intStream
                .mapToObj(index -> {
                    return pheEngine.rawEncrypt(pk, BigInteger.valueOf(Math.abs(secureRandom.nextInt() >> 1)));
                })
                .toArray(BigInteger[]::new);

        stopWatch.stop();
        long encryptionTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        System.out.println("Time to encrypt: "+encryptionTime + " ms.");

        BigInteger x = BigInteger.valueOf(Math.abs(secureRandom.nextInt() >> 1));
        BigInteger rr = BigIntegerUtils.randomPositive(modulus.shiftRight(1), secureRandom);

        stopWatch.start();
        IntStream intStream1 = IntStream.range(0, size);
        intStream1 = parallel ? intStream1.parallel() : intStream1;
        BigInteger[] c1 = intStream1
                .mapToObj(index -> {
                    return pheEngine.rawMultiply(pk, rawCiphertexts[index], x);
                })
                .toArray(BigInteger[]::new);

        IntStream intStream2 = IntStream.range(0, size);
        intStream2 = parallel ? intStream2.parallel() : intStream2;
        BigInteger[] c2 = intStream2
                .mapToObj(index -> {
                    return pheEngine.rawMultiply(pk, rawCiphertexts[index], rr);
                })
                .toArray(BigInteger[]::new);
        stopWatch.stop();
        long aheTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        System.out.println("Time to compute the tuple (2 plain/cipher mult): "+aheTime + " ms.");



        BigInteger[] rs = randomZn2(size, modulus, secureRandom);


        stopWatch.start();
        pipelineReRand(pk, rawCiphertexts, rs);
        pipelineReRand(pk, c1, rs);
        pipelineReRand(pk, c2, rs);
        stopWatch.stop();
        long reRandTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        System.out.println("reRandTime: "+reRandTime + " ms.");
    }

    static {
        System.loadLibrary(CommonConstants.MPC4J_NATIVE_FHE_NAME);
    }

//    public static void testBFV(){
//        List<byte[]> encryptionParams = Merpsu22AhePsuNativeUtils.genEncryptionParameters(
//                4096, 40961, new int[]{24, 24, 24}
//        );
//        List<byte[]> fheParams = encryptionParams.subList(0, 2);
//        System.out.println(fheParams.get(0));
//
////        Merpsu22AhePsuNativeUtils.sayHello();
//
//    }

    public static void main(String[] args) {
        System.out.println("Hello, World!");
//        testBFV();
    }
}
