package edu.alibaba.mpc4j.common.tool.okve.ovdm.zpm;

import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.Zp;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.ZpFactory;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.ZpLinearSolver;

import java.math.BigInteger;
import java.security.SecureRandom;

/**
 * Z_p^m-OVDM Abstract Class
 *
 * @author Anonymous
 * @date 2023/03/01
 */

public abstract class AbstractZpmOvdm<T> implements ZpmOvdm<T> {
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
     * Zp有限域
     */
    protected final Zp zp;
    /**
     * Zp线性求解器
     */
    protected final ZpLinearSolver zpLinearSolver;
    /**
     * Zp有限域
     */
    protected final int polyDegree;
    /**
     * 编码过程所用到的随机状态
     */
    protected final SecureRandom secureRandom;

    protected AbstractZpmOvdm(EnvType envType, BigInteger prime, int n, int m, int polyDegree) {
        assert n > 0 : "n must be greater than 0: " + n;
        this.n = n;
        zp = ZpFactory.createInstance(envType, prime);
        zpLinearSolver = new ZpLinearSolver(zp);
        // 要求m >= n，且m可以被Byte.SIZE整除
        assert m >= n && m % Byte.SIZE == 0;
        this.m = m;
        mByteLength = m / Byte.SIZE;
        secureRandom = new SecureRandom();
        this.polyDegree = polyDegree;
    }

    @Override
    public int getN() {
        return n;
    }

    @Override
    public int getM() { return m; }
}
