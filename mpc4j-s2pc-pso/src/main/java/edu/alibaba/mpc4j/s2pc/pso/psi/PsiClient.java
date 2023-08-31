package edu.alibaba.mpc4j.s2pc.pso.psi;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.pto.SecurePto;
import edu.alibaba.mpc4j.common.rpc.pto.TwoPartyPto;

import java.util.Set;

/**
 * PSI协议客户端接口。
 *
 * @author Weiran Liu
 * @date 2022/9/19
 */
public interface PsiClient<T> extends TwoPartyPto, SecurePto {
    /**
     * 返回PSI协议类型。
     *
     * @return PSI协议类型。
     */
    @Override
    PsiFactory.PsiType getPtoType();

    /**
     * 初始化协议。
     *
     * @param maxClientElementSize 客户端最大元素数量。
     * @param maxServerElementSize 服务端最大元素数量。
     * @throws MpcAbortException 如果协议异常中止。
     */
    void init(int maxClientElementSize, int maxServerElementSize) throws MpcAbortException;

    /**
     * 执行协议。
     *
     * @param clientElementSet  客户端元素集合。
     * @param serverElementSize 服务端元素数量。
     * @return 协议输出结果。
     * @throws MpcAbortException 如果协议异常中止。
     */
    Set<T> psi(Set<T> clientElementSet, int serverElementSize) throws MpcAbortException;
}
