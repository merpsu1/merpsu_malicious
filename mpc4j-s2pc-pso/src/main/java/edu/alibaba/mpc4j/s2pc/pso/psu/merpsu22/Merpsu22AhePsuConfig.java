package edu.alibaba.mpc4j.s2pc.pso.psu.merpsu22;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.zn.ZnOvdmFactory.ZnOvdmType;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.core.CoreCotConfig;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.core.CoreCotFactory;
import edu.alibaba.mpc4j.s2pc.pso.psu.PsuConfig;
import edu.alibaba.mpc4j.s2pc.pso.psu.PsuFactory.PsuType;

/**
 * Merpsu22-AHE-PSU协议配置项。
 *
 * @author Anonymous
 * @date 2022/10/28
 */
public class Merpsu22AhePsuConfig implements PsuConfig {
    /**
     * 核COT协议配置项
     */
    private final CoreCotConfig coreCotConfig;
    /**
     * Zn-OVDM类型
     */
    private final ZnOvdmType znOvdmType;
    /**
     * 流水线数量
     */
    private final int pipeSize;

    private Merpsu22AhePsuConfig(Merpsu22AhePsuConfig.Builder builder) {
        coreCotConfig = builder.coreCotConfig;
        znOvdmType = builder.znOvdmType;
        pipeSize = builder.pipeSize;
    }

    @Override
    public void setEnvType(EnvType envType){coreCotConfig.setEnvType(envType);
    }

    @Override
    public EnvType getEnvType() {return coreCotConfig.getEnvType();}

    @Override
    public SecurityModel getSecurityModel() {
        SecurityModel securityModel = SecurityModel.SEMI_HONEST;
        if (coreCotConfig.getSecurityModel().compareTo(securityModel) < 0) {
            securityModel = coreCotConfig.getSecurityModel();
        }
        return securityModel;
    }
    @Override
    public PsuType getPtoType() {
        return PsuType.MERPSU22_AHE;
    }

    public ZnOvdmType getZnOvdmType() {
        return znOvdmType;
    }

    public int getPipeSize() {
        return pipeSize;
    }


    public static class Builder implements org.apache.commons.lang3.builder.Builder<Merpsu22AhePsuConfig> {
        /**
         * 核COT协议配置项
         */
        private CoreCotConfig coreCotConfig;
        /**
         * Zn-OVDM类型
         */
        private ZnOvdmType znOvdmType;
//        /**
//         * ECC-OVDM类型
//         */
//        private EccOvdmType eccOvdmType;
//        /**
//         * 是否使用压缩椭圆曲线编码
//         */
//        private boolean compressEncode;
        /**
         * 流水线数量
         */
        private int pipeSize;

        public Builder() {
            coreCotConfig = CoreCotFactory.createDefaultConfig(SecurityModel.SEMI_HONEST);
            znOvdmType = ZnOvdmType.H3_SINGLETON_GCT;
//            eccOvdmType = EccOvdmType.H3_SINGLETON_GCT;
//            compressEncode = true;
            pipeSize = (1 << 8);
        }

        public Merpsu22AhePsuConfig.Builder setCoreCotConfig(CoreCotConfig coreCotConfig) {
            this.coreCotConfig = coreCotConfig;
            return this;
        }
        public Merpsu22AhePsuConfig.Builder setZnOvdmType(ZnOvdmType znOvdmType) {
            this.znOvdmType = znOvdmType;
//            this.znOvdmType = ZnOvdmFactory.getRelatedEccOvdmType(znOvdmType);
            return this;
        }

//        public Merpsu22AhePsuConfig.Builder setEccOvdmType(EccOvdmType eccOvdmType) {
//            this.eccOvdmType = eccOvdmType;
//            this.znOvdmType = EccOvdmFactory.getRelatedEccOvdmType(eccOvdmType);
//            return this;
//        }

//        public Merpsu22AhePsuConfig.Builder setCompressEncode(boolean compressEncode) {
//            this.compressEncode = compressEncode;
//            return this;
//        }

        public Merpsu22AhePsuConfig.Builder setPipeSize(int pipeSize) {
            assert pipeSize > 0 : "Pipeline Size must be greater than 0: " + pipeSize;
            this.pipeSize = pipeSize;
            return this;
        }

        @Override
        public Merpsu22AhePsuConfig build() {
            return new Merpsu22AhePsuConfig(this);
        }
    }
}

