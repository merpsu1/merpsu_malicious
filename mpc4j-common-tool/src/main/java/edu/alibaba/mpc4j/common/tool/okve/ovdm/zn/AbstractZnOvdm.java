package edu.alibaba.mpc4j.common.tool.okve.ovdm.zn;

import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.galoisfield.zn.Zn;
import edu.alibaba.mpc4j.common.tool.galoisfield.zn.ZnFactory;
import edu.alibaba.mpc4j.common.tool.galoisfield.zn.ZnLinearSolver;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Zn-OVDM抽象类。
 *
 * @author Weiran Liu
 * @date 2021/10/01
 */
public abstract class AbstractZnOvdm<T> implements ZnOvdm<T> {
    /**
     * OVDM允许编码的键值对数量
     */
    protected final int n;
    /**
     * OVDM长度，满足{@code m % Byte.SIZE == 0}。
     */
    protected final int m;
    /**
     * m的字节长度
     */
    final int mByteLength;
    /**
     * Zn有限域
     */
    protected final Zn zn;
    /**
     * Zn线性求解器
     */
    protected final ZnLinearSolver znLinearSolver;
    /**
     * 编码过程所用到的随机状态
     */
    protected final SecureRandom secureRandom;

    protected AbstractZnOvdm(EnvType envType, BigInteger N, int n, int m) {
        assert n > 0 : "n must be greater than 0: " + n;
        this.n = n;
        zn = ZnFactory.createInstance(envType, N);
        znLinearSolver = new ZnLinearSolver(zn);
        // 要求m >= n，且m可以被Byte.SIZE整除
        assert m >= n && m % Byte.SIZE == 0;
        this.m = m;
        mByteLength = m / Byte.SIZE;
        secureRandom = new SecureRandom();
    }

    @Override
    public int getN() {
        return n;
    }

    @Override
    public int getM() { return m; }
}

