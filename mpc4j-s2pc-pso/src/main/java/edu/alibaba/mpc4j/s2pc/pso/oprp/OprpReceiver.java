package edu.alibaba.mpc4j.s2pc.pso.oprp;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.pto.SecurePto;
import edu.alibaba.mpc4j.common.rpc.pto.TwoPartyPto;
import edu.alibaba.mpc4j.common.tool.crypto.prp.PrpFactory.PrpType;
import edu.alibaba.mpc4j.s2pc.pso.oprp.OprpFactory.OprpType;

/**
 * Oprp接收方接口。
 *
 * @author Weiran Liu
 * @date 2022/02/11
 */
public interface OprpReceiver extends TwoPartyPto, SecurePto {

    @Override
    OprpType getPtoType();

    /**
     * 返回PRP类型。
     *
     * @return PRP类型。
     */
    PrpType getPrpType();

    /**
     * 返回协议是否为逆映射。
     *
     * @return 协议是否为逆映射。
     */
    boolean isInvPrp();

    /**
     * 初始化协议。
     *
     * @param maxBatchSize 最大批处理数量。
     * @throws MpcAbortException 如果协议异常中止。
     */
    void init(int maxBatchSize) throws MpcAbortException;

    /**
     * 执行协议。
     *
     * @param messages 明文。
     * @return 接收方输出。
     * @throws MpcAbortException 如果协议异常中止。
     */
    OprpReceiverOutput oprp(byte[][] messages) throws MpcAbortException;
}
