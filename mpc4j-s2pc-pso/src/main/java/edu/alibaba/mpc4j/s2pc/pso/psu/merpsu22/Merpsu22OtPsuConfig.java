package edu.alibaba.mpc4j.s2pc.pso.psu.merpsu22;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.ecc.EccOvdmFactory;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.ecc.EccOvdmFactory.EccOvdmType;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.zp.ZpOvdmFactory.ZpOvdmType;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.core.CoreCotConfig;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.core.CoreCotFactory;
import edu.alibaba.mpc4j.s2pc.pso.psu.PsuConfig;
import edu.alibaba.mpc4j.s2pc.pso.psu.PsuFactory.PsuType;

/**
 * Merpsu22-OT-PSU协议配置项。
 *
 * @author Anonymous
 * @date 2022/10/28
 */
public class Merpsu22OtPsuConfig implements PsuConfig {
    /**
     * 核COT协议配置项
     */
    private final CoreCotConfig coreCotConfig;
    /**
     * Zp-OVDM类型
     */
    private final ZpOvdmType zpOvdmType;
    /**
     * ECC-OVDM类型
     */
    private final EccOvdmType eccOvdmType;
    /**
     * 是否使用压缩椭圆曲线编码
     */
    private final boolean compressEncode;
    /**
     * 流水线数量
     */
    private final int pipeSize;

    private Merpsu22OtPsuConfig(Builder builder) {
        coreCotConfig = builder.coreCotConfig;
        zpOvdmType = builder.zpOvdmType;
        eccOvdmType = builder.eccOvdmType;
        compressEncode = builder.compressEncode;
        pipeSize = builder.pipeSize;
    }

    @Override
    public PsuType getPtoType() {
        return PsuType.MERPSU22_OT;
    }

    public CoreCotConfig getCoreCotConfig() {
        return coreCotConfig;
    }

    public ZpOvdmType getZpOvdmType() {
        return zpOvdmType;
    }

    public EccOvdmType getEccOvdmType() {
        return eccOvdmType;
    }

    public boolean getCompressEncode() {
        return compressEncode;
    }

    public int getPipeSize() {
        return pipeSize;
    }

    @Override
    public void setEnvType(EnvType envType) {
        coreCotConfig.setEnvType(envType);
    }

    @Override
    public EnvType getEnvType() {
        return coreCotConfig.getEnvType();
    }

    @Override
    public SecurityModel getSecurityModel() {
        SecurityModel securityModel = SecurityModel.SEMI_HONEST;
        if (coreCotConfig.getSecurityModel().compareTo(securityModel) < 0) {
            securityModel = coreCotConfig.getSecurityModel();
        }
        return securityModel;
    }

    public static class Builder implements org.apache.commons.lang3.builder.Builder<Merpsu22OtPsuConfig> {
        /**
         * 核COT协议配置项
         */
        private CoreCotConfig coreCotConfig;
        /**
         * Zp-OVDM类型
         */
        private ZpOvdmType zpOvdmType;
        /**
         * ECC-OVDM类型
         */
        private EccOvdmType eccOvdmType;
        /**
         * 是否使用压缩椭圆曲线编码
         */
        private boolean compressEncode;
        /**
         * 流水线数量
         */
        private int pipeSize;

        public Builder() {
            coreCotConfig = CoreCotFactory.createDefaultConfig(SecurityModel.SEMI_HONEST);
            zpOvdmType = ZpOvdmType.H3_SINGLETON_GCT;
            eccOvdmType = EccOvdmType.H3_SINGLETON_GCT;
            compressEncode = true;
            pipeSize = (1 << 8);
        }

        public Builder setCoreCotConfig(CoreCotConfig coreCotConfig) {
            this.coreCotConfig = coreCotConfig;
            return this;
        }

        public Builder setEccOvdmType(EccOvdmType eccOvdmType) {
            this.eccOvdmType = eccOvdmType;
            this.zpOvdmType = EccOvdmFactory.getRelatedEccOvdmType(eccOvdmType);
            return this;
        }

        public Builder setCompressEncode(boolean compressEncode) {
            this.compressEncode = compressEncode;
            return this;
        }

        public Builder setPipeSize(int pipeSize) {
            assert pipeSize > 0 : "Pipeline Size must be greater than 0: " + pipeSize;
            this.pipeSize = pipeSize;
            return this;
        }

        @Override
        public Merpsu22OtPsuConfig build() {
            return new Merpsu22OtPsuConfig(this);
        }
    }
}


