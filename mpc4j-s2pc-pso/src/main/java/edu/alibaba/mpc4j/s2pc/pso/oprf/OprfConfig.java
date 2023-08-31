package edu.alibaba.mpc4j.s2pc.pso.oprf;

import edu.alibaba.mpc4j.common.rpc.pto.SecurePtoConfig;

/**
 * OPRF协议配置项。
 *
 * @author Weiran Liu
 * @date 2022/02/06
 */
public interface OprfConfig extends SecurePtoConfig {
    /**
     * 返回协议类型。
     *
     * @return 协议类型。
     */
    OprfFactory.OprfType getPtoType();
}
