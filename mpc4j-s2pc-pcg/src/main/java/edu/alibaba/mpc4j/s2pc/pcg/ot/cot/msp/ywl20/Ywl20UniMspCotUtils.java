package edu.alibaba.mpc4j.s2pc.pcg.ot.cot.msp.ywl20;

import edu.alibaba.mpc4j.common.tool.hashbin.primitive.cuckoo.IntCuckooHashBinFactory.IntCuckooHashBinType;

/**
 * YWL20-UNI-MSP-COT协议工具类。
 *
 * @author Weiran Liu
 * @date 2022/5/15
 */
public class Ywl20UniMspCotUtils {

    private Ywl20UniMspCotUtils() {
        // empty
    }

    /**
     * 布谷鸟哈希类型
     */
    public static final IntCuckooHashBinType INT_CUCKOO_HASH_BIN_TYPE = IntCuckooHashBinType.NO_STASH_NAIVE;
}
