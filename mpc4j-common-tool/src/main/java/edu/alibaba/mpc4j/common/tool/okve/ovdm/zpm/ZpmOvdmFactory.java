package edu.alibaba.mpc4j.common.tool.okve.ovdm.zpm;

import com.google.common.base.Preconditions;
import edu.alibaba.mpc4j.common.tool.EnvType;

import java.math.BigInteger;

/**
 * Zpm-OVDM factory。
 *
 * @author Anonymous
 * @date 2023/03/01
 */

public class ZpmOvdmFactory {
    /**
     * 私有构造函数
     */
    private ZpmOvdmFactory() {
        // empty
    }

    /**
     * Zp-OVDM类型。
     */
    public enum ZpmOvdmType {
//        /**
//         * 2哈希-两核乱码布谷鸟表
//         */
//        H2_TWO_CORE_GCT,
//        /**
//         * 2哈希-单例乱码布谷鸟表
//         */
//        H2_SINGLETON_GCT,
        /**
         * 3哈希-单例乱码布谷鸟表
         */
        H3_SINGLETON_GCT,
    }

    /**
     * 构建Zp-OVDM。
     *
     * @param envType 环境类型。
     * @param type    Zp-OVDM类型。
     * @param p       模数p。
     * @param n       待编码的键值对数量。
     * @param keys    哈希密钥。
     * @return Zp-OVDM。
     */
    public static <X> ZpmOvdm<X> createInstance(EnvType envType, ZpmOvdmFactory.ZpmOvdmType type, BigInteger p,
                                                int n, byte[][] keys, int polyDegree) {
        assert keys.length == getHashNum(type);
        switch (type) {
            case H3_SINGLETON_GCT:
                return new H3TcGctZpmOvdm<>(envType, p, n, keys,polyDegree);
//            case H2_SINGLETON_GCT:
//                return new H2TcGctZpmOvdm<>(envType, p, n, keys, new CuckooTableSingletonTcFinder<>());
//            case H2_TWO_CORE_GCT:
//                return new H2TcGctZpmOvdm<>(envType, p, n, keys, new H2CuckooTableTcFinder<>());
            default:
                throw new IllegalArgumentException("Invalid ZpmOvdmType: " + type.name());
        }
    }

    /**
     * 返回Zp-OVDM的哈希函数数量。
     *
     * @param ZpmOvdmType Zp-OVDM类型。
     * @return 哈希函数数量。
     */
    public static int getHashNum(ZpmOvdmFactory.ZpmOvdmType ZpmOvdmType) {
        switch (ZpmOvdmType) {
            case H3_SINGLETON_GCT:
                return H3TcGctZpmOvdm.HASH_NUM;
//            case H2_SINGLETON_GCT:
//            case H2_TWO_CORE_GCT:
//                return H2TcGctZpmOvdm.HASH_NUM;
            default:
                throw new IllegalArgumentException("Invalid ZpmOvdmType: " + ZpmOvdmType.name());
        }
    }

    /**
     * 返回Zp-OVDM的长度m，m为Byte.SIZE的整数倍。
     *
     * @param ZpmOvdmType Zp-OVDM类型。
     * @param n          待编码的键值对数量。
     * @return Zp-OVDM的长度m。
     */
    public static int getM(ZpmOvdmFactory.ZpmOvdmType ZpmOvdmType, int n) {
        Preconditions.checkArgument(n > 0);
        switch (ZpmOvdmType) {
            case H3_SINGLETON_GCT:
                return H3TcGctZpmOvdm.getLm(n) + H3TcGctZpmOvdm.getRm(n);
//            case H2_SINGLETON_GCT:
//            case H2_TWO_CORE_GCT:
//                return H2TcGctZpmOvdm.getLm(n) + H2TcGctZpmOvdm.getRm(n);
            default:
                throw new IllegalArgumentException("Invalid ZpmOvdmType: " + ZpmOvdmType.name());
        }
    }

}
