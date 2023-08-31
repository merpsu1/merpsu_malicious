package edu.alibaba.mpc4j.common.tool.galoisfield.zn;

import edu.alibaba.mpc4j.common.tool.EnvType;

import java.math.BigInteger;

/**
 * Zn有限域工厂。
 *
 * @author Weiran Liu
 * @date 2022/9/22
 */
public class ZnFactory {
    /**
     * Zn有限域类型
     */
    public enum ZnType {
        /**
         * JDK实现的Zn运算
         */
        JDK,
    }

//    /**
//     * 创建Zn运算实例。
//     *
//     * @param type 类型。
//     * @param l    l比特长度。
//     * @return Zn运算实例。
//     */
//    public static Zn createInstance(EnvType envType, edu.alibaba.mpc4j.common.tool.galoisfield.zn.ZnFactory.ZnType type, int l) {
//        //noinspection SwitchStatementWithTooFewBranches
//        switch (type) {
//            case JDK:
//                return new JdkZn(envType, l);
//            default:
//                throw new IllegalArgumentException("Invalid " + edu.alibaba.mpc4j.common.tool.galoisfield.zn.ZnFactory.ZnType.class.getSimpleName() + ": " + type.name());
//        }
//    }

    /**
     * 创建Zn运算实例。
     *
     * @param type  类型。
     * @param N 素数。
     * @return Zn运算实例。
     */
    public static Zn createInstance(EnvType envType, edu.alibaba.mpc4j.common.tool.galoisfield.zn.ZnFactory.ZnType type, BigInteger N) {
        //noinspection SwitchStatementWithTooFewBranches
        switch (type) {
            case JDK:
                return new JdkZn(envType, N);
            default:
                throw new IllegalArgumentException("Invalid " + edu.alibaba.mpc4j.common.tool.galoisfield.zn.ZnFactory.ZnType.class.getSimpleName() + ": " + type.name());
        }
    }

//    /**
//     * 创建Zn运算实例。
//     *
//     * @param envType 环境类型。
//     * @param l       l比特长度。
//     * @return Zn运算实例。
//     */
//    public static Zn createInstance(EnvType envType, int l) {
//        switch (envType) {
//            case STANDARD:
//            case INLAND:
//            case STANDARD_JDK:
//            case INLAND_JDK:
//                return new JdkZn(envType, l);
//            default:
//                throw new IllegalArgumentException("Invalid " + EnvType.class.getSimpleName() + ": " + envType.name());
//        }
//    }

    /**
     * 创建Zn运算实例。
     *
     * @param envType 环境类型。
     * @param N   质数。
     * @return Zn运算实例。
     */
    public static Zn createInstance(EnvType envType, BigInteger N) {
        switch (envType) {
            case STANDARD:
            case INLAND:
            case STANDARD_JDK:
            case INLAND_JDK:
                return new JdkZn(envType, N);
            default:
                throw new IllegalArgumentException("Invalid " + EnvType.class.getSimpleName() + ": " + envType.name());
        }
    }
}
