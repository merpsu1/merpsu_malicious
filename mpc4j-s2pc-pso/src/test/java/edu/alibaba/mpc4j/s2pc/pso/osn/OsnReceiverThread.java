package edu.alibaba.mpc4j.s2pc.pso.osn;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;

/**
 * 不经意交换网络接收方线程。
 *
 * @author Weiran Liu
 * @date 2021/09/20
 */
public class OsnReceiverThread extends Thread {
    /**
     * 接收方
     */
    private final OsnReceiver osnReceiver;
    /**
     * 输入/分享字节长度
     */
    private final int byteLength;
    /**
     * 交换方式
     */
    private final int[] permutationMap;
    /**
     * 输出
     */
    private OsnPartyOutput receiverOutput;

    OsnReceiverThread(OsnReceiver osnReceiver, int[] permutationMap, int byteLength) {
        this.osnReceiver = osnReceiver;
        this.byteLength = byteLength;
        this.permutationMap = permutationMap;
    }

    OsnPartyOutput getReceiverOutput() {
        return receiverOutput;
    }

    @Override
    public void run() {
        try {
            osnReceiver.getRpc().connect();
            osnReceiver.init(permutationMap.length);
            receiverOutput = osnReceiver.osn(permutationMap, byteLength);
            osnReceiver.getRpc().disconnect();
        } catch (MpcAbortException e) {
            e.printStackTrace();
        }
    }
}
