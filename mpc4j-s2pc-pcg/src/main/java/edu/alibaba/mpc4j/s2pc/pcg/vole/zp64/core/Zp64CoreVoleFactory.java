package edu.alibaba.mpc4j.s2pc.pcg.vole.zp64.core;

import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.pto.PtoFactory;
import edu.alibaba.mpc4j.s2pc.pcg.vole.zp64.core.kos16.Kos16ShZp64CoreVoleConfig;
import edu.alibaba.mpc4j.s2pc.pcg.vole.zp64.core.kos16.Kos16ShZp64CoreVoleReceiver;
import edu.alibaba.mpc4j.s2pc.pcg.vole.zp64.core.kos16.Kos16ShZp64CoreVoleSender;

/**
 * Zp64-核VOLE协议工厂类。
 *
 * @author Hanwen Feng
 * @date 2022/06/15
 */
public class Zp64CoreVoleFactory implements PtoFactory {
    /**
     * 私有构造函数。
     */
    private Zp64CoreVoleFactory() {
        // empty
    }

    /**
     * 协议类型。
     */
    public enum Zp64CoreVoleType {
        /**
         * KOS16半诚实安全协议
         */
        KOS16_SEMI_HONEST,
        /**
         * KOS16恶意安全协议
         */
        KOS16_MALICIOUS,
    }

    /**
     * 构建发送方。
     *
     * @param senderRpc     发送方通信接口。
     * @param receiverParty 接收方信息。
     * @param config        配置项。
     * @return 发送方。
     */
    public static Zp64CoreVoleSender createSender(Rpc senderRpc, Party receiverParty, Zp64CoreVoleConfig config) {
        Zp64CoreVoleType type = config.getPtoType();
        switch (type) {
            case KOS16_SEMI_HONEST:
                return new Kos16ShZp64CoreVoleSender(senderRpc, receiverParty, (Kos16ShZp64CoreVoleConfig) config);
            case KOS16_MALICIOUS:
            default:
                throw new IllegalArgumentException("Invalid " + Zp64CoreVoleType.class.getSimpleName() + ": " + type.name());
        }
    }

    /**
     * 构建接收方。
     *
     * @param receiverRpc 接收方通信接口。
     * @param senderParty 发送方信息。
     * @param config      配置项。
     * @return 接收方。
     */
    public static Zp64CoreVoleReceiver createReceiver(Rpc receiverRpc, Party senderParty, Zp64CoreVoleConfig config) {
        Zp64CoreVoleType type = config.getPtoType();
        switch (type) {
            case KOS16_SEMI_HONEST:
                return new Kos16ShZp64CoreVoleReceiver(receiverRpc, senderParty, (Kos16ShZp64CoreVoleConfig) config);
            case KOS16_MALICIOUS:
            default:
                throw new IllegalArgumentException("Invalid " + Zp64CoreVoleType.class.getSimpleName() + ": " + type.name());
        }
    }
}
