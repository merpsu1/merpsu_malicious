package edu.alibaba.mpc4j.common.tool.okve.ovdm.zn;

import com.google.common.base.Preconditions;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.zn.ZnOvdmFactory.ZnOvdmType;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.IntStream;

/**
 * Zn-OVDM测试。
 *
 * @author Weiran Liu
 * @date 2022/01/09
 */
@RunWith(Parameterized.class)
public class ZnOvdmTest {
    /**
     * 默认键值对数量
     */
    private static final int DEFAULT_N = 10;
    /**
     * 随机测试轮数
     */
    private static final int MAX_RANDOM_ROUND = 10;

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> configurations() {
        Collection<Object[]> configurationParams = new ArrayList<>();
//        // H2_TWO_CORE_GCT
//        configurationParams.add(new Object[]{ZnOvdmType.H2_TWO_CORE_GCT.name(), ZnOvdmType.H2_TWO_CORE_GCT});
//        // H2_SINGLETON_GCT
//        configurationParams.add(new Object[]{ZnOvdmType.H2_SINGLETON_GCT.name(), ZnOvdmType.H2_SINGLETON_GCT});
        // H3_SINGLETON_GCT
        configurationParams.add(new Object[]{ZnOvdmType.H3_SINGLETON_GCT.name(), ZnOvdmType.H3_SINGLETON_GCT});

        return configurationParams;
    }

    /**
     * GF(2^l)-OVDM类型
     */
    private final ZnOvdmType type;

    public ZnOvdmTest(String name, ZnOvdmType type) {
        Preconditions.checkArgument(StringUtils.isNotBlank(name));
        this.type = type;
    }

    @Test
    public void testIllegalInputs() {
        // 尝试设置错误数量的密钥
        if (ZnOvdmFactory.getHashNum(type) > 0) {
            byte[][] moreKeys = CommonUtils.generateRandomKeys(
                    ZnOvdmFactory.getHashNum(type) + 1, ZnOvdmTestUtils.SECURE_RANDOM);
            try {
                ZnOvdmFactory.createInstance(
                        EnvType.STANDARD, type, ZnOvdmTestUtils.DEFAULT_MOD, DEFAULT_N, moreKeys
                );
                throw new IllegalStateException("ERROR: successfully create OVDM with more keys");
            } catch (AssertionError ignored) {

            }
            byte[][] lessKeys = CommonUtils.generateRandomKeys(
                    ZnOvdmFactory.getHashNum(type) - 1, ZnOvdmTestUtils.SECURE_RANDOM
            );
            try {
                ZnOvdmFactory.createInstance(
                        EnvType.STANDARD, type, ZnOvdmTestUtils.DEFAULT_MOD, DEFAULT_N, lessKeys
                );
                throw new IllegalStateException("ERROR: successfully create OVDM with less keys");
            } catch (AssertionError ignored) {

            }
        }
        byte[][] keys = CommonUtils.generateRandomKeys(ZnOvdmFactory.getHashNum(type), ZnOvdmTestUtils.SECURE_RANDOM);
        // 尝试让n = 0
        try {
            ZnOvdmFactory.createInstance(EnvType.STANDARD, type, ZnOvdmTestUtils.DEFAULT_MOD, 0, keys);
            throw new IllegalStateException("ERROR: successfully create OVDM with n = 0");
        } catch (AssertionError ignored) {

        }
        ZnOvdm<ByteBuffer> ovdm = ZnOvdmFactory.createInstance(
                EnvType.STANDARD, type, ZnOvdmTestUtils.DEFAULT_MOD, DEFAULT_N, keys
        );
        // 尝试编码更多的元素
        Map<ByteBuffer, BigInteger> keyValueMap = ZnOvdmTestUtils.randomKeyValueMap(DEFAULT_N + 1);
        IntStream.range(0, DEFAULT_N + 1).forEach(index -> {
            byte[] keyBytes = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
            ZnOvdmTestUtils.SECURE_RANDOM.nextBytes(keyBytes);
            BigInteger value = BigIntegerUtils.randomPositive(
                    ZnOvdmTestUtils.DEFAULT_MOD, ZnOvdmTestUtils.SECURE_RANDOM
            );
            keyValueMap.put(ByteBuffer.wrap(keyBytes), value);
        });
        try {
            ovdm.encode(keyValueMap);
            throw new IllegalStateException("ERROR: successfully encode key-value map with more elements");
        } catch (AssertionError ignored) {

        }
    }

    @Test
    public void testType() {
        byte[][] keys = CommonUtils.generateRandomKeys(ZnOvdmFactory.getHashNum(type), ZnOvdmTestUtils.SECURE_RANDOM);
        ZnOvdm<ByteBuffer> ovdm = ZnOvdmFactory.createInstance(
                EnvType.STANDARD, type, ZnOvdmTestUtils.DEFAULT_MOD, DEFAULT_N, keys
        );
        Assert.assertEquals(type, ovdm.getZnOvdmType());
    }

    @Test
    public void test1n() {
        testOvdm(1);
    }

    @Test
    public void test2n() {
        testOvdm(2);
    }

    @Test
    public void test3n() {
        testOvdm(3);
    }

    @Test
    public void test40n() {
        testOvdm(40);
    }

    @Test
    public void test256n() {
        testOvdm(256);
    }

    @Test
    public void test4096n() {
        testOvdm(4096);
    }

    private void testOvdm(int n) {
        for (int round = 0; round < MAX_RANDOM_ROUND; round++) {
            // 生成密钥
            byte[][] keys = CommonUtils.generateRandomKeys(
                    ZnOvdmFactory.getHashNum(type), ZnOvdmTestUtils.SECURE_RANDOM
            );
            // 创建OVDM实例
            ZnOvdm<ByteBuffer> odvm = ZnOvdmFactory.createInstance(
                    EnvType.STANDARD, type, ZnOvdmTestUtils.DEFAULT_MOD, n, keys
            );
            // 生成随机键值对
            Map<ByteBuffer, BigInteger> keyValueMap = ZnOvdmTestUtils.randomKeyValueMap(n);
            // 编码
            BigInteger[] storage = odvm.encode(keyValueMap);
            // 并发解码，验证结果
            keyValueMap.keySet().stream().parallel().forEach(key -> {
                BigInteger value = keyValueMap.get(key);
                BigInteger decodeValue = odvm.decode(storage, key);
                Assert.assertEquals(value, decodeValue);
            });
            // 验证随机输入的解码结果不在值集合中
            Set<BigInteger> valueSet = new HashSet<>(keyValueMap.values());
            IntStream.range(0, MAX_RANDOM_ROUND).forEach(index -> {
                // 生成比特长度为安全常数的x，生成l比特长的y，插入到Map中
                byte[] randomKeyBytes = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
                ZnOvdmTestUtils.SECURE_RANDOM.nextBytes(randomKeyBytes);
                ByteBuffer randomKey = ByteBuffer.wrap(randomKeyBytes);
                if (!keyValueMap.containsKey(randomKey)) {
                    BigInteger randomDecodeValue = odvm.decode(storage, randomKey);
                    Assert.assertFalse(valueSet.contains(randomDecodeValue));
                }
            });
        }
    }
}

