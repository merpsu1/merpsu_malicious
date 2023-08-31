package edu.alibaba.mpc4j.common.tool.okve.ovdm.zn;

import com.google.common.base.Preconditions;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.okve.cuckootable.CuckooTableSingletonTcFinder;
import edu.alibaba.mpc4j.common.tool.okve.cuckootable.H2CuckooTableTcFinder;

import java.math.BigInteger;


/**
 * Zn-OVDM工厂。
 *
 * @author Weiran Liu
 * @date 2021/10/01
 */
public class ZnOvdmFactory {
    /**
     * 私有构造函数
     */
    private ZnOvdmFactory() {
        // empty
    }

    /**
     * Zn-OVDM类型。
     */
    public enum ZnOvdmType {
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
     * 构建Zn-OVDM。
     *
     * @param envType 环境类型。
     * @param type    Zn-OVDM类型。
     * @param N       模数N。
     * @param n       待编码的键值对数量。
     * @param keys    哈希密钥。
     * @return Zn-OVDM。
     */
    public static <X> ZnOvdm<X> createInstance(EnvType envType, edu.alibaba.mpc4j.common.tool.okve.ovdm.zn.ZnOvdmFactory.ZnOvdmType type, BigInteger N, int n, byte[][] keys) {
        assert keys.length == getHashNum(type);
        switch (type) {
            case H3_SINGLETON_GCT:
                return new H3TcGctZnOvdm<>(envType, N, n, keys);
//            case H2_SINGLETON_GCT:
//                return new H2TcGctZnOvdm<>(envType, p, n, keys, new CuckooTableSingletonTcFinder<>());
//            case H2_TWO_CORE_GCT:
//                return new H2TcGctZnOvdm<>(envType, p, n, keys, new H2CuckooTableTcFinder<>());
            default:
                throw new IllegalArgumentException("Invalid ZnOvdmType: " + type.name());
        }
    }

    /**
     * 返回Zn-OVDM的哈希函数数量。
     *
     * @param ZnOvdmType Zn-OVDM类型。
     * @return 哈希函数数量。
     */
    public static int getHashNum(edu.alibaba.mpc4j.common.tool.okve.ovdm.zn.ZnOvdmFactory.ZnOvdmType ZnOvdmType) {
        switch (ZnOvdmType) {
            case H3_SINGLETON_GCT:
                return H3TcGctZnOvdm.HASH_NUM;
//            case H2_SINGLETON_GCT:
//            case H2_TWO_CORE_GCT:
//                return H2TcGctZnOvdm.HASH_NUM;
            default:
                throw new IllegalArgumentException("Invalid ZnOvdmType: " + ZnOvdmType.name());
        }
    }

    /**
     * 返回Zn-OVDM的长度m，m为Byte.SIZE的整数倍。
     *
     * @param ZnOvdmType Zn-OVDM类型。
     * @param n          待编码的键值对数量。
     * @return Zn-OVDM的长度m。
     */
    public static int getM(edu.alibaba.mpc4j.common.tool.okve.ovdm.zn.ZnOvdmFactory.ZnOvdmType ZnOvdmType, int n) {
        Preconditions.checkArgument(n > 0);
        switch (ZnOvdmType) {
            case H3_SINGLETON_GCT:
                return H3TcGctZnOvdm.getLm(n) + H3TcGctZnOvdm.getRm(n);
//            case H2_SINGLETON_GCT:
//            case H2_TWO_CORE_GCT:
//                return H2TcGctZnOvdm.getLm(n) + H2TcGctZnOvdm.getRm(n);
            default:
                throw new IllegalArgumentException("Invalid ZnOvdmType: " + ZnOvdmType.name());
        }
    }
}
