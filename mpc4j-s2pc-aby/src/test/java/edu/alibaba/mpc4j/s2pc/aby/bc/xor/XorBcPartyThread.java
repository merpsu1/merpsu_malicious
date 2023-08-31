package edu.alibaba.mpc4j.s2pc.aby.bc.xor;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.s2pc.aby.bc.BcSquareVector;
import edu.alibaba.mpc4j.s2pc.aby.bc.BcParty;

/**
 * XOR-BC协议参与方线程。
 *
 * @author Weiran Liu
 * @date 2022/02/14
 */
class XorBcPartyThread extends Thread {
    /**
     * BC协议参与方
     */
    private final BcParty bcParty;
    /**
     * xi
     */
    private final BcSquareVector xi;
    /**
     * yi
     */
    private final BcSquareVector yi;
    /**
     * 运算数量
     */
    private final int num;
    /**
     * zi
     */
    private BcSquareVector zi;

    XorBcPartyThread(BcParty bcParty, BcSquareVector xi, BcSquareVector yi) {
        this.bcParty = bcParty;
        assert xi.bitLength() == yi.bitLength();
        this.xi = xi;
        this.yi = yi;
        num = xi.bitLength();
    }

    BcSquareVector getPartyOutput() {
        return zi;
    }

    @Override
    public void run() {
        try {
            bcParty.getRpc().connect();
            bcParty.init(num, num);
            zi = bcParty.xor(xi, yi);
            bcParty.getRpc().disconnect();
        } catch (MpcAbortException e) {
            e.printStackTrace();
        }
    }
}
