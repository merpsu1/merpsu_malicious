package edu.alibaba.mpc4j.s2pc.pcg.ot.cot.msp.bcg19;

import edu.alibaba.mpc4j.common.rpc.desc.PtoDesc;
import edu.alibaba.mpc4j.common.rpc.desc.PtoDescManager;

/**
 * BCG19-REG-MSP-COT协议信息。下述论文
 * <p>
 * Yang, Kang, Chenkai Weng, Xiao Lan, Jiang Zhang, and Xiao Wang. Ferret: Fast extension for correlated OT with small
 * communication. CCS 2020, pp. 1607-1626. 2020.
 * </p>
 * 第6章前有一段描述：
 * <p>
 * Protocol Π_{MPCOT} described in Figure 7 assumes that the receiver’s input Q can be any t-sized subset of [n].
 * However, if we assume that LPN with a regular noise distribution, then the set Q is more restricted in which there
 * will be exactly one index in each interval U_i = [i * n / t, (i + 1) * n / t) for i ∈ [t]. In this case, we can
 * construct a more efficient MPCOT protocol by directly using SPCOT. In particular, we can just call F_{SPCOT} t times,
 * each corresponds to an interval U_i of size n/t. The final output is the concatenation of all t output vectors.
 * </p>
 * 经过考察，此方案最初来自于下述论文：
 * <p>
 * Boyle, Elette, Geoffroy Couteau, Niv Gilboa, Yuval Ishai, Lisa Kohl, Peter Rindal, and Peter Scholl. Efficient
 * two-round OT extension and silent non-interactive secure computation. CCS 2019, pp. 291-308. 2019.
 * </p>
 *
 * @author Weiran Liu
 * @date 2022/01/25
 */
class Bcg19RegMspCotPtoDesc implements PtoDesc {
    /**
     * 协议ID
     */
    private static final int PTO_ID = Math.abs((int) 5132887582232393843L);
    /**
     * 协议名称
     */
    private static final String PTO_NAME = "BCG19_REG_MSP_COT";

    /**
     * 单例模式
     */
    private static final Bcg19RegMspCotPtoDesc INSTANCE = new Bcg19RegMspCotPtoDesc();

    /**
     * 私有构造函数
     */
    private Bcg19RegMspCotPtoDesc() {
        // empty
    }

    public static PtoDesc getInstance() {
        return INSTANCE;
    }

    static {
        PtoDescManager.registerPtoDesc(getInstance());
    }

    @Override
    public int getPtoId() {
        return PTO_ID;
    }

    @Override
    public String getPtoName() {
        return PTO_NAME;
    }
}
