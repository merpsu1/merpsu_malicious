package edu.alibaba.mpc4j.common.tool.utils;

import edu.alibaba.mpc4j.common.jnagmp.Gmp;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.SecureRandom;
import java.util.Random;
import java.util.Arrays;

/**
 * 大整数工具类，主要完成很多代数计算。
 * 部分代码来自于：
 * https://github.com/n1analytics/javallier/blob/master/src/main/java/com/n1analytics/paillier/util/BigIntegerUtil.java
 *
 * @author Weiran Liu
 * @date 2020/09/19
 */
public class BigIntegerUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(BigIntegerUtils.class);
    /**
     * 用{@code BigInteger}表示的最小{@code long}值
     */
    public static final BigInteger LONG_MIN_VALUE = BigInteger.valueOf(Long.MIN_VALUE);
    /**
     * 用{@code BigInteger}表示的最大{@code long}值
     */
    public static final BigInteger LONG_MAX_VALUE = BigInteger.valueOf(Long.MAX_VALUE);
    /**
     * 用{@code BigInteger}表示的最小{@code int}值
     */
    public static final BigInteger INT_MIN_VALUE = BigInteger.valueOf(Integer.MIN_VALUE);
    /**
     * 用{@code BigInteger}表示的最大{@code int}值
     */
    public static final BigInteger INT_MAX_VALUE = BigInteger.valueOf(Integer.MAX_VALUE);
    /**
     * 2的大整数表示
     */
    public static final BigInteger BIGINT_2 = BigInteger.valueOf(2);
    /**
     * 如果可以成功调用GMP库，则此变量将被设置为true
     */
    public static final boolean USE_GMP;

    /*
     * 检查是否可以使用GMP库
     */
    static {
        USE_GMP = canLoadGmp();
    }

    /**
     * 尝试载入GMP库。如果成功，返回true，否则返回false。
     *
     * @return 是否可以成功载入GMP库。
     */
    private static boolean canLoadGmp() {
        try {
            Gmp.checkLoaded();
            return true;
        } catch (Error e) {
            LOGGER.warn("无法载入GMP库，将使用Java原生modPow函数实现模幂运算，性能较差", e);
            return false;
        }
    }

    /**
     * 私有构造函数。
     */
    private BigIntegerUtils() {
        // empty
    }

    /**
     * 将{@code BigInteger}转换为{@code byte[]}，大端表示。注意：转换过程已经对数据进行了拷贝。
     *
     * @param bigInteger 待转换的{@code BigInteger}。
     * @return 转换结果。
     */
    public static byte[] bigIntegerToByteArray(BigInteger bigInteger) {
        return bigInteger.toByteArray();
    }

    /**
     * 将{@code byte[]}转换为{@code BigInteger}。
     * <p>注意：如果{@code byte[]}的首位包含0，转换时会自动忽略，这将导致恢复成{@code byte[]}时与原{@code byte[]}不相等。
     *
     * @param byteArray 待转换的{@code byte[]}。
     * @return 转换结果。
     */
    public static BigInteger byteArrayToBigInteger(final byte[] byteArray) {
        return new BigInteger(byteArray);
    }

    /**
     * 将非负数的{@code BigInteger}转换为{@code byte[]}，大端表示。
     *
     * @param nonNegBigInteger 待转换的非负数{@code BigInteger}。
     * @param byteLength       指定转换结果的字节长度。
     * @return 转换结果。
     */
    public static byte[] nonNegBigIntegerToByteArray(BigInteger nonNegBigInteger, int byteLength) {
        if (nonNegBigInteger.equals(BigInteger.ZERO)) {
            return new byte[byteLength];
        }
        int inputByteLength = CommonUtils.getByteLength(nonNegBigInteger.bitLength());
        assert inputByteLength <= byteLength
            : "input byte length must be less than or equal to " + byteLength + ": " + inputByteLength;
        assert BigIntegerUtils.greaterOrEqual(nonNegBigInteger, BigInteger.ZERO);
        byte[] directByteArray = nonNegBigInteger.toByteArray();
        byte[] resultByteArray = new byte[byteLength];
        int startLength;
        int copyLength;
        if (nonNegBigInteger.bitLength() > 0 && nonNegBigInteger.bitLength() % Byte.SIZE == 0) {
            /*
             * BigInteger.toByteArray()是大端表示，第一个元素是符号位，正数的符号位是0。
             * 如果BigInteger的有效比特数（bigLength）正好可以整除Byte.SIZE，则转换结果会在最前面多添加1个全0的byte，可以拿掉。
             */
            startLength = 1;
            copyLength = directByteArray.length - 1;
        } else {
            startLength = 0;
            copyLength = directByteArray.length;
        }
        System.arraycopy(directByteArray, startLength, resultByteArray, byteLength - copyLength, copyLength);
        return resultByteArray;
    }

    /**
     * 将BigInteger[]形式的数据转换为byte[][]形式的数据。
     *
     * @param nonNegBigIntegers 待转换的非负数数组{@code BigInteger[]}。
     * @param byteLength        字节长度。
     * @return 转换结果。
     */
    public static byte[][] nonNegBigIntegersToByteArrays(BigInteger[] nonNegBigIntegers, int byteLength) {
        return Arrays.stream(nonNegBigIntegers)
            .map(x -> BigIntegerUtils.nonNegBigIntegerToByteArray(x, byteLength))
            .toArray(byte[][]::new);
    }

    /**
     * 将{@code byte[]}转换为非负数的{@code BigInteger}。注意：转换过程已经对数据进行了拷贝。
     *
     * @param byteArray 待转换的{@code byte[]}。
     * @return 转换结果。
     */
    public static BigInteger byteArrayToNonNegBigInteger(byte[] byteArray) {
        return new BigInteger(1, byteArray);
    }

    /**
     * 将byte[][]形式的数据转换为BigInteger[]形式的数据。
     *
     * @param xs         byte[][]形式的数据。
     * @return 转换结果。
     */
    public static BigInteger[] byteArraysToNonNegBigIntegers(byte[][] xs) {
        return Arrays.stream(xs)
            .map(BigIntegerUtils::byteArrayToNonNegBigInteger)
            .toArray(BigInteger[]::new);
    }

    /**
     * 模幂预算。如果系统支持调用GMP库，则会调用GMP库完成运算。此函数无法抵抗侧信道攻击。
     *
     * @param base     底数。
     * @param exponent 幂。
     * @param modulus  模数。
     * @return (base ^ exponent) mod modulus。
     */
    public static BigInteger modPow(BigInteger base, BigInteger exponent, BigInteger modulus) {
        if (USE_GMP) {
            // Gmp library can't handle negative exponents
            return exponent.signum() < 0
                ? BigIntegerUtils.modInverse(Gmp.modPowInsecure(base, exponent.negate(), modulus), modulus)
                : Gmp.modPowInsecure(base, exponent, modulus);
        } else {
            return base.modPow(exponent, modulus);
        }
    }

    /**
     * 计算模b条件下a的乘法逆元。
     *
     * @param a       待求逆的数。
     * @param modulus 模数。
     * @return a^(-1)，满足a * a^(-1) == 1 mod modulus。
     * @throws ArithmeticException 如果乘法逆元不存在。
     */
    public static BigInteger modInverse(BigInteger a, BigInteger modulus) throws ArithmeticException {
        if (USE_GMP) {
            return Gmp.modInverse(a, modulus);
        } else {
            return a.modInverse(modulus);
        }
    }

    /**
     * 检查{@code n}是否为正数。
     *
     * @param n 待检查的数。
     * @return 如果{@code n}为正数，返回true；否则，返回false。
     */
    public static boolean positive(BigInteger n) {
        return n.signum() > 0;
    }

    /**
     * 检查{@code n}是否为非负数。
     *
     * @param n 待检查的数。
     * @return 如果{@code n}为正数或0，返回true；否则，返回false。
     */
    public static boolean nonNegative(BigInteger n) {
        return n.signum() >= 0;
    }

    /**
     * 检查{@code n}是否为负数。
     *
     * @param n 待检查的数。
     * @return 如果{@code n}为负数，返回true；否则，返回false。
     */
    public static boolean negative(BigInteger n) {
        return n.signum() < 0;
    }

    /**
     * 检查{@code n}是否为非正数。
     *
     * @param n 待检查的数。
     * @return 如果{@code n}为负数或0，返回true；否则，返回false。
     */
    public static boolean nonPositive(BigInteger n) {
        return n.signum() <= 0;
    }

    /**
     * 检查{@code a}是否大于{@code b}。
     *
     * @param a 第1个数。
     * @param b 第2个数。
     * @return 如果{@code a}大于{@code b}，返回true；否则，返回false。
     */
    public static boolean greater(BigInteger a, BigInteger b) {
        return a.compareTo(b) > 0;
    }

    /**
     * 检查{@code a}是否大于或等于{@code b}。
     *
     * @param a 第1个数。
     * @param b 第2个数。
     * @return 如果{@code a}大于或等于{@code b}，返回true；否则，返回false。
     */
    public static boolean greaterOrEqual(BigInteger a, BigInteger b) {
        return a.compareTo(b) >= 0;
    }

    /**
     * 检查{@code a}是否小于{@code b}。
     *
     * @param a 第1个数。
     * @param b 第2个数。
     * @return 如果{@code a}小于{@code b}，返回true；否则，返回false。
     */
    public static boolean less(BigInteger a, BigInteger b) {
        return a.compareTo(b) < 0;
    }

    /**
     * 检查{@code a}是否小于等于{@code b}。
     *
     * @param a 第1个数。
     * @param b 第2个数。
     * @return 如果{@code a}小于等于{@code b}，返回true；否则，返回false。
     */
    public static boolean lessOrEqual(BigInteger a, BigInteger b) {
        return a.compareTo(b) <= 0;
    }

    /**
     * 返回一个属于[1, n)的随机数。
     *
     * @param n            上界。
     * @param secureRandom 随机状态。
     * @return 随机数。
     */
    public static BigInteger randomPositive(final BigInteger n, SecureRandom secureRandom) {
        assert BigIntegerUtils.greater(n, BigInteger.ONE) : "n must be greater than 1:" + n;
        int bits = n.bitLength();
        while (true) {
            BigInteger r = new BigInteger(bits, secureRandom);
            if (BigIntegerUtils.less(r, BigInteger.ONE) || BigIntegerUtils.greaterOrEqual(r, n)) {
                continue;
            }
            return r;
        }
    }

    /**
     * 返回一个属于[1, n)的随机数。
     *
     * @param n            上界。
     * @param random 随机状态。
     * @return 随机数。
     */
    public static BigInteger randomPositive(final BigInteger n, Random random) {
        assert BigIntegerUtils.greater(n, BigInteger.ONE) : "n must be greater than 1:" + n;
        int bits = n.bitLength();
        while (true) {
            BigInteger r = new BigInteger(bits, random);
            if (BigIntegerUtils.less(r, BigInteger.ONE) || BigIntegerUtils.greaterOrEqual(r, n)) {
                continue;
            }
            return r;
        }
    }

    /**
     * 返回一个属于[0, n)的随机数。
     *
     * @param n            上界。
     * @param secureRandom 随机状态。
     * @return 随机数。
     */
    public static BigInteger randomNonNegative(final BigInteger n, SecureRandom secureRandom) {
        assert BigIntegerUtils.greater(n, BigInteger.ZERO) : "n must be greater than 0:" + n;
        int bits = n.bitLength();
        while (true) {
            // r必然属于[0, 2^k)，只需要进一步判断是否小于n
            BigInteger r = new BigInteger(bits, secureRandom);
            if (BigIntegerUtils.greaterOrEqual(r, n)) {
                continue;
            }
            return r;
        }
    }

    /**
     * 计算{@code BigInteger n}开平方的整数部分。核心代码来自于Faruk Akgul，并进行了一些调整：
     * http://faruk.akgul.org/blog/javas-missing-algorithm-biginteger-sqrt/
     *
     * @param n 待开平方的数。
     * @return {@code n}开平方的整数部分。
     */
    public static BigInteger sqrt(BigInteger n) {
        assert BigIntegerUtils.greater(n, BigInteger.ZERO);
        if (n.equals(BigInteger.ONE)) {
            return BigInteger.ONE;
        }
        BigInteger a = BigInteger.ONE;
        BigInteger b = n.shiftRight(5).add(BigInteger.valueOf(8));
        while (b.compareTo(a) >= 0) {
            BigInteger mid = a.add(b).shiftRight(1);
            if (mid.multiply(mid).compareTo(n) > 0) {
                b = mid.subtract(BigInteger.ONE);
            } else {
                a = mid.add(BigInteger.ONE);
            }
        }
        return a.subtract(BigInteger.ONE);
    }

    /**
     * 计算组合数：从n个不同元素中任取m ≤ n个元素所有可能的个数，用符号C(n, m)表示。
     *
     * @param n 共有n个元素。
     * @param m 选择m个元素。
     * @return C(n, m)的值。
     */
    public static BigInteger combinatorial(int n, int m) {
        assert m >= 0 && m <= n;
        BigInteger combinatoral = BigInteger.ONE;
        // C(n, m) = C(n, n - m)，选择小的m
        int minM = m > n / 2 ? n - m : m;
        for (int i = 1; i <= minM; i++) {
            combinatoral = combinatoral.multiply(BigInteger.valueOf(n + 1 - i));
            combinatoral = combinatoral.divide(BigInteger.valueOf(i));
        }
        return combinatoral;
    }

    /**
     * 计算log_2(x)。
     * 代码源自Maarten Bodewes (http://stackoverflow.com/questions/739532/logarithm-of-a-bigdecimal)。
     *
     * @param x 输入值。
     * @return log_2(x)。
     */
    public static double log2(BigInteger x) {
        assert BigIntegerUtils.greater(x, BigInteger.ZERO);
        if (x.equals(BigInteger.ONE)) {
            return 0.0;
        }
        // Get the minimum number of bits necessary to hold this value.
        int n = x.bitLength();
        /*
         * Calculate the double-precision fraction of this number; as if the binary point was left of the most significant
         * '1' bit. (Get the most significant 53 bits and divide by 2^53).
         * Note that mantissa is 53 bits (including hidden bit).
         */
        long mask = 1L << 52;
        long mantissa = 0;
        int j = 0;
        for (int i = 1; i < 54; i++) {
            j = n - i;
            if (j < 0) {
                break;
            }
            if (x.testBit(j)) {
                mantissa |= mask;
            }
            mask >>>= 1;
        }
        // Round up if next bit is 1.
        if (j > 0 && x.testBit(j - 1)) {
            mantissa++;
        }
        double f = mantissa / (double) (1L << 52);
        /*
         * Add the logarithm to the number of bits, and subtract 1 because the number of bits is always higher than
         * necessary for a number (i.e. log_2(x) < n for every x).
         * Note that magic number converts from base e to base 2 before adding. For other bases, correct the result,
         * NOT this number!
         */
        return (n - 1 + Math.log(f) * 1.44269504088896340735992468100189213742664595415298D);
    }
}
