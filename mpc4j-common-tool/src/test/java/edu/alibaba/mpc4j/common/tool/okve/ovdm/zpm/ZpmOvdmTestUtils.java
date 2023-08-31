package edu.alibaba.mpc4j.common.tool.okve.ovdm.zpm;

import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.ZpManager;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

public class ZpmOvdmTestUtils {
    /**
     * 私有构造函数
     */
    private ZpmOvdmTestUtils() {
        // empty
    }

    /**
     * 默认质数
     */
    static final BigInteger DEFAULT_PRIME = ZpManager.getPrime(CommonConstants.BLOCK_BIT_LENGTH * 2);
    /**
     * 随机状态
     */
    static final SecureRandom SECURE_RANDOM = new SecureRandom();

    static Map<ByteBuffer, BigInteger[]> randomKeyValueMap(int size, int polyDegree) {
        Map<ByteBuffer, BigInteger[]> keyValueMap = new HashMap<>();
        IntStream.range(0, size).forEach(index -> {
            byte[] keyBytes = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
            SECURE_RANDOM.nextBytes(keyBytes);
            BigInteger[] values = new BigInteger[polyDegree];
            for (int i=0;i<polyDegree; i++){
                values[i] = BigIntegerUtils.randomPositive(DEFAULT_PRIME, SECURE_RANDOM);
            }
            keyValueMap.put(ByteBuffer.wrap(keyBytes), values);
        });
        return keyValueMap;
    }
}
