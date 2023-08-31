package edu.alibaba.mpc4j.common.tool.galoisfield.zn;


import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.crypto.kdf.Kdf;
import edu.alibaba.mpc4j.common.tool.crypto.kdf.KdfFactory;
import edu.alibaba.mpc4j.common.tool.crypto.prg.Prg;
import edu.alibaba.mpc4j.common.tool.crypto.prg.PrgFactory;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;

import java.math.BigInteger;
import java.security.SecureRandom;


/**
 * 应用JDK实现的Zn。
 *
 * @author Weiran Liu
 * @date 2022/9/22
 */
class JdkZn implements Zn {
    /**
     * Modulus
     */
    private final BigInteger N;
    /**
     * Modulus比特长度
     */
    private final int NBitLength;
    /**
     * Modulus字节长度
     */
    private final int NByteLength;
    /**
     * l比特长度
     */
    private final int l;
    /**
     * l字节长度
     */
    private final int byteL;
    /**
     * 最大有效元素：2^l
     */
    private final BigInteger rangeBound;
    /**
     * KDF
     */
    private final Kdf kdf;
    /**
     * 伪随机数生成器
     */
    private final Prg prg;

    /**
     * Modulus为输入的构造函数。
     *
     * @param envType 环境类型。
     * @param N   Modulus。
     */
    public JdkZn(EnvType envType, BigInteger N) {
        this.N = N;
        NBitLength = N.bitLength();
        NByteLength = CommonUtils.getByteLength(NBitLength);
        l = NBitLength - 1;
        byteL = CommonUtils.getByteLength(l);
        rangeBound = BigInteger.ONE.shiftLeft(l);
        kdf = KdfFactory.createInstance(envType);
        prg = PrgFactory.createInstance(envType, NByteLength);
    }

//    /**
//     * 有效比特为输入的构造函数。
//     *
//     * @param envType 环境类型。
//     * @param l       有效比特长度。
//     */
//    public JdkZp(EnvType envType, int l) {
//        prime = ZpManager.getPrime(l);
//        primeBitLength = prime.bitLength();
//        primeByteLength = CommonUtils.getByteLength(primeBitLength);
//        this.l = l;
//        byteL = CommonUtils.getByteLength(l);
//        rangeBound = BigInteger.ONE.shiftLeft(l);
//        kdf = KdfFactory.createInstance(envType);
//        prg = PrgFactory.createInstance(envType, Long.BYTES);
//    }

    @Override
    public ZnFactory.ZnType getZnType() {
        return ZnFactory.ZnType.JDK;
    }

    @Override
    public BigInteger getN() {
        return N;
    }

    @Override
    public int getL() {
        return l;
    }

    @Override
    public int getByteL() {
        return byteL;
    }

    @Override
    public int getNBitLength() {
        return NBitLength;
    }

    @Override
    public int getNByteLength() {
        return NByteLength;
    }

    @Override
    public BigInteger getRangeBound() {
        return rangeBound;
    }

    @Override
    public BigInteger module(final BigInteger a) {
        return a.mod(N);
    }

    @Override
    public BigInteger add(final BigInteger a, final BigInteger b) {
        assert validateElement(a) : "a is not a valid element in Zn: " + a;
        assert validateElement(b) : "b is not a valid element in Zn: " + b;
        return a.add(b).mod(N);
    }

    @Override
    public BigInteger neg(final BigInteger a) {
        assert validateElement(a) : "a is not a valid element in Zn: " + a;
        if (a.equals(BigInteger.ZERO)) {
            return BigInteger.ZERO;
        } else {
            return N.subtract(a);
        }
    }

    @Override
    public BigInteger sub(final BigInteger a, final BigInteger b) {
        assert validateElement(a) : "a is not a valid element in Zn: " + a;
        assert validateElement(b) : "b is not a valid element in Zn: " + b;
        return a.subtract(b).mod(N);
    }

    @Override
    public BigInteger mul(final BigInteger a, final BigInteger b) {
        assert validateElement(a) : "a is not a valid element in Zn: " + a;
        assert validateElement(b) : "b is not a valid element in Zn: " + b;
        return a.multiply(b).mod(N);
    }

    @Override
    public BigInteger div(final BigInteger a, final BigInteger b) {
        assert validateElement(a) : "a is not a valid element in Zn: " + a;
        assert validateNonZeroElement(b) : "a is not a valid non-zero element in Zn: " + a;
        return a.multiply(BigIntegerUtils.modInverse(b, N)).mod(N);
    }

    @Override
    public BigInteger inv(final BigInteger a) {
        assert validateNonZeroElement(a) : "a is not a valid non-zero element in Zn: " + a;
        return BigIntegerUtils.modInverse(a, N);
    }

    @Override
    public BigInteger mulPow(final BigInteger a, final BigInteger b) {
        assert validateElement(a) : "a is not a valid element in Zn: " + a;
        assert validateElement(b) : "b is not a valid element in Zn: " + b;
        return BigIntegerUtils.modPow(a, b, N);
    }

    @Override
    public BigInteger innerProduct(final BigInteger[] znVector, final boolean[] binaryVector) {
        assert znVector.length == binaryVector.length
                : "Zn vector length must be equal to binary vector length = " + binaryVector.length + ": " + znVector.length;
        BigInteger value = BigInteger.ZERO;
        for (int i = 0; i < znVector.length; i++) {
            if (binaryVector[i]) {
                value = add(value, znVector[i]);
            }
        }
        return value;
    }

    @Override
    public BigInteger createRandom(SecureRandom secureRandom) {
        return BigIntegerUtils.randomNonNegative(N, secureRandom);
    }

    @Override
    public BigInteger createRandom(byte[] seed) {
        byte[] key = kdf.deriveKey(seed);
        byte[] elementByteArray = prg.extendToBytes(key);
        return BigIntegerUtils.byteArrayToNonNegBigInteger(elementByteArray).mod(N);
    }

    @Override
    public BigInteger createNonZeroRandom(SecureRandom secureRandom) {
        BigInteger random = BigInteger.ZERO;
        while (random.equals(BigInteger.ZERO)) {
            random = BigIntegerUtils.randomPositive(N, secureRandom);
        }
        return random;
    }

    @Override
    public BigInteger createNonZeroRandom(byte[] seed) {
        byte[] key = kdf.deriveKey(seed);
        byte[] elementByteArray = prg.extendToBytes(key);
        BigInteger random = BigIntegerUtils.byteArrayToNonNegBigInteger(elementByteArray).mod(N);
        while (random.equals(BigInteger.ZERO)) {
            // 如果恰巧为0，则迭代种子
            key = kdf.deriveKey(key);
            elementByteArray = prg.extendToBytes(key);
            random = BigIntegerUtils.byteArrayToNonNegBigInteger(elementByteArray).mod(N);
        }
        return random;
    }

    @Override
    public BigInteger[] createMultipleNonZeroRandom(byte[] seed, int m) {
        BigInteger[] random = new BigInteger[m];
        byte[] key = kdf.deriveKey(seed);
        for (int i=0; i<m; i++){
            byte[] elementByteArray = prg.extendToBytes(key);
            random[i] = BigIntegerUtils.byteArrayToNonNegBigInteger(elementByteArray).mod(N);
            while (random[i].equals(BigInteger.ZERO)) {
                // 如果恰巧为0，则迭代种子
                key = kdf.deriveKey(key);
                elementByteArray = prg.extendToBytes(key);
                random[i] = BigIntegerUtils.byteArrayToNonNegBigInteger(elementByteArray).mod(N);
            }
            key = kdf.deriveKey(key);
        }
        return random;
    }

    @Override
    public BigInteger createRangeRandom(SecureRandom secureRandom) {
        return BigIntegerUtils.randomNonNegative(rangeBound, secureRandom);
    }

    @Override
    public BigInteger createRangeRandom(byte[] seed) {
        byte[] key = kdf.deriveKey(seed);
        byte[] elementByteArray = prg.extendToBytes(key);
        return BigIntegerUtils.byteArrayToNonNegBigInteger(elementByteArray).mod(rangeBound);
    }

    @Override
    public boolean validateElement(final BigInteger a) {
        return BigIntegerUtils.greaterOrEqual(a, BigInteger.ZERO) && BigIntegerUtils.less(a, N);
    }

    @Override
    public boolean validateNonZeroElement(final BigInteger a) {
        return BigIntegerUtils.greater(a, BigInteger.ZERO) && BigIntegerUtils.less(a, N);
    }

    @Override
    public boolean validateRangeElement(final BigInteger a) {
        return BigIntegerUtils.greaterOrEqual(a, BigInteger.ZERO) && BigIntegerUtils.less(a, rangeBound);
    }
}

