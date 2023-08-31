package edu.alibaba.mpc4j.s2pc.pso.pmid;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;

import java.util.Map;

/**
 * 服务端集合PMID协议客户端线程。
 *
 * @author Weiran Liu
 * @date 2022/05/10
 */
public class ServerSetPmidClientThread extends Thread {
    /**
     * PMID客户端
     */
    private final PmidClient<String> pmidClient;
    /**
     * 客户端映射
     */
    private final Map<String, Integer> clientElementMap;
    /**
     * 服务端集合数量
     */
    private final int serverSetSize;
    /**
     * 客户端重数上界
     */
    private final int maxClientU;
    /**
     * PMID输出结果
     */
    private PmidPartyOutput<String> clientOutput;

    ServerSetPmidClientThread(PmidClient<String> pmidClient,
                              Map<String, Integer> clientElementMap, int maxClientU, int serverSetSize) {
        this.pmidClient = pmidClient;
        this.clientElementMap = clientElementMap;
        this.maxClientU = maxClientU;
        this.serverSetSize = serverSetSize;
    }

    PmidPartyOutput<String> getClientOutput() {
        return clientOutput;
    }

    @Override
    public void run() {
        try {
            pmidClient.getRpc().connect();
            pmidClient.init(clientElementMap.keySet().size(), maxClientU, serverSetSize, 1);
            clientOutput = pmidClient.pmid(clientElementMap, serverSetSize);
            pmidClient.getRpc().disconnect();
        } catch (MpcAbortException e) {
            e.printStackTrace();
        }
    }
}
