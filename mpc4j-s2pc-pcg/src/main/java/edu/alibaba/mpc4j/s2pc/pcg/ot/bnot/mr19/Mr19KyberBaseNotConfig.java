package edu.alibaba.mpc4j.s2pc.pcg.ot.bnot.mr19;

import edu.alibaba.mpc4j.common.rpc.desc.SecurityModel;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.crypto.kyber.KyberEngineFactory.KyberType;
import edu.alibaba.mpc4j.common.tool.crypto.kyber.params.KyberParams;
import edu.alibaba.mpc4j.s2pc.pcg.ot.bnot.BaseNotConfig;
import edu.alibaba.mpc4j.s2pc.pcg.ot.bnot.BaseNotFactory;

/**
 * MR19-Kyber-基础n选1-OT协议配置项。
 *
 * @author Sheng Hu, Weiran Liu
 * @date 2022/08/25
 */
public class Mr19KyberBaseNotConfig implements BaseNotConfig {
    /**
     * Kyber安全系数
     */
    private final int paramsK;
    /**
     * Kyber方案类型
     */
    private final KyberType kyberType;
    /**
     * 环境类型
     */
    private EnvType envType;

    private Mr19KyberBaseNotConfig(Builder builder) {
        assert KyberParams.validParamsK(builder.paramsK) : KyberParams.INVALID_PARAMS_K_ERROR_MESSAGE + builder.paramsK;
        paramsK = builder.paramsK;
        kyberType = builder.kyberType;
        envType = EnvType.STANDARD;
    }

    @Override
    public BaseNotFactory.BaseNotType getPtoType() {
        return BaseNotFactory.BaseNotType.MR19_KYBER;
    }

    @Override
    public void setEnvType(EnvType envType) {
        this.envType = envType;
    }

    @Override
    public EnvType getEnvType() {
        return envType;
    }

    @Override
    public SecurityModel getSecurityModel() {
        return SecurityModel.MALICIOUS;
    }

    public int getParamsK() {
        return paramsK;
    }

    public KyberType getKyberType() {
        return kyberType;
    }

    public static class Builder implements org.apache.commons.lang3.builder.Builder<Mr19KyberBaseNotConfig> {
        /**
         * Kyber安全系数
         */
        private int paramsK;
        /**
         * 方案类型
         */
        private KyberType kyberType;

        public Builder() {
            paramsK = 4;
            kyberType = KyberType.KYBER_CCA;
        }

        public Builder setParamsK(int paramsK) {
            this.paramsK = paramsK;
            return this;
        }

        public Builder setKyberType(KyberType kyberType) {
            this.kyberType = kyberType;
            return this;
        }

        @Override
        public Mr19KyberBaseNotConfig build() {
            return new Mr19KyberBaseNotConfig(this);
        }
    }
}
