package edu.alibaba.mpc4j.s2pc.pcg.ot.cot.nc.ywl20;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.core.CoreCotConfig;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.core.CoreCotFactory;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.nc.NcCotConfig;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.msp.MspCotConfig;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.msp.MspCotFactory;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.nc.NcCotFactory;

/**
 * YWL20-NC-COT协议配置项。
 *
 * @author Weiran Liu
 * @date 2022/01/27
 */
public class Ywl20NcCotConfig implements NcCotConfig {
    /**
     * 核COT协议配置项
     */
    private final CoreCotConfig coreCotConfig;
    /**
     * MSP-COT协议配置项
     */
    private final MspCotConfig mspCotConfig;

    private Ywl20NcCotConfig(Builder builder) {
        // 两个协议的环境配型必须相同
        assert builder.coreCotConfig.getEnvType().equals(builder.mspCotConfig.getEnvType());
        coreCotConfig = builder.coreCotConfig;
        mspCotConfig = builder.mspCotConfig;
    }

    public CoreCotConfig getCoreCotConfig() {
        return coreCotConfig;
    }

    public MspCotConfig getMspCotConfig() {
        return mspCotConfig;
    }

    @Override
    public NcCotFactory.NcCotType getPtoType() {
        return NcCotFactory.NcCotType.YWL20;
    }

    @Override
    public int maxAllowNum() {
        return 1 << Ywl20NcCotPtoDesc.MAX_LOG_N;
    }

    @Override
    public void setEnvType(EnvType envType) {
        coreCotConfig.setEnvType(envType);
        mspCotConfig.setEnvType(envType);
    }

    @Override
    public EnvType getEnvType() {
        return mspCotConfig.getEnvType();
    }

    @Override
    public SecurityModel getSecurityModel() {
        SecurityModel securityModel = SecurityModel.MALICIOUS;
        if (coreCotConfig.getSecurityModel().compareTo(securityModel) < 0) {
            securityModel = coreCotConfig.getSecurityModel();
        }
        if (mspCotConfig.getSecurityModel().compareTo(securityModel) < 0) {
            securityModel = mspCotConfig.getSecurityModel();
        }
        return securityModel;
    }

    public static class Builder implements org.apache.commons.lang3.builder.Builder<Ywl20NcCotConfig> {
        /**
         * 核COT协议配置项
         */
        private CoreCotConfig coreCotConfig;
        /**
         * MSP-COT协议配置项
         */
        private MspCotConfig mspCotConfig;

        public Builder(SecurityModel securityModel) {
            coreCotConfig = CoreCotFactory.createDefaultConfig(securityModel);
            mspCotConfig = MspCotFactory.createDefaultConfig(securityModel);
        }

        public Builder setCoreCotConfig(CoreCotConfig coreCotConfig) {
            this.coreCotConfig = coreCotConfig;
            return this;
        }

        public Builder setMspCotConfig(MspCotConfig mspCotConfig) {
            this.mspCotConfig = mspCotConfig;
            return this;
        }

        @Override
        public Ywl20NcCotConfig build() {
            return new Ywl20NcCotConfig(this);
        }
    }
}
