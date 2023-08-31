package edu.alibaba.mpc4j.s2pc.pso.psu.merpsu22;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacket;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.crypto.crhf.Crhf;
import edu.alibaba.mpc4j.common.tool.crypto.crhf.CrhfFactory;
import edu.alibaba.mpc4j.common.tool.crypto.crhf.CrhfFactory.CrhfType;
import edu.alibaba.mpc4j.common.tool.crypto.ecc.Ecc;
import edu.alibaba.mpc4j.common.tool.crypto.ecc.EccFactory;
import edu.alibaba.mpc4j.common.tool.crypto.prg.Prg;
import edu.alibaba.mpc4j.common.tool.crypto.prg.PrgFactory;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.ecc.EccOvdm;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.ecc.EccOvdmFactory;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.ecc.EccOvdmFactory.EccOvdmType;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.CotSenderOutput;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.core.CoreCotFactory;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.core.CoreCotSender;
import edu.alibaba.mpc4j.s2pc.pso.psu.AbstractPsuServer;
import org.bouncycastle.math.ec.ECPoint;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * Merpsu22-OT-PSU协议发送方。
 *
 * @author Anonymous
 * @date 2022/10/28
 */

public class Merpsu22OtPsuServer extends AbstractPsuServer {
    /**
     * 核COT协议发送方
     */
    private final CoreCotSender coreCotSender;
    /**
     * ECC-OVDM类型
     */
    private final EccOvdmFactory.EccOvdmType eccOvdmType;
    /**
     * 是否使用压缩椭圆曲线编码
     */
    private final boolean compressEncode;
    /**
     * 流水线数量
     */
    private final int pipeSize;
    /**
     * 椭圆曲线
     */
    private final Ecc ecc;
    /**
     * 抗关联哈希函数
     */
    private final Crhf crhf;
    /**
     * ECC-OVDM哈希密钥
     */
    private byte[][] eccOvdmHashKeys;
    /**
     * 公钥
     */
    private ECPoint y;
    /**
     * 密文OVDM
     */
    private EccOvdm<ByteBuffer> eccOvdm;
    /**
     * OVDM密文存储
     */
    private ECPoint[] kemOvdmStorage;
    /**
     * OVDM负载存储
     */
    private ECPoint[] ctOvdmStorage;

    public Merpsu22OtPsuServer(Rpc serverRpc, Party clientParty, Merpsu22OtPsuConfig config) {
        super(Merpsu22OtPsuPtoDesc.getInstance(), serverRpc, clientParty, config);
        coreCotSender = CoreCotFactory.createSender(serverRpc, clientParty, config.getCoreCotConfig());
        coreCotSender.addLogLevel();
        eccOvdmType = config.getEccOvdmType();
        compressEncode = config.getCompressEncode();
        pipeSize = config.getPipeSize();
        ecc = EccFactory.createInstance(getEnvType());
        crhf = CrhfFactory.createInstance(getEnvType(), CrhfFactory.CrhfType.MMO);
    }

    @Override
    public void setTaskId(long taskId) {
        super.setTaskId(taskId);
        coreCotSender.setTaskId(taskId);
    }

    @Override
    public void setParallel(boolean parallel) {
        super.setParallel(parallel);
        coreCotSender.setParallel(parallel);
    }

    @Override
    public void addLogLevel() {
        super.addLogLevel();
        coreCotSender.addLogLevel();
    }

    @Override
    public void init(int maxServerElementSize, int maxClientElementSize) throws MpcAbortException {
        setInitInput(maxServerElementSize, maxClientElementSize);
        info("{}{} Server Init begin********************", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        stopWatch.start();
        // 初始化各个子协议
        byte[] delta = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
        secureRandom.nextBytes(delta);
        coreCotSender.init(delta, maxServerElementSize);
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Init Step 1/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), initTime);

        stopWatch.start();
        List<byte[]> keysPayload = new LinkedList<>();
        // 初始化Gf2x-OVDM密钥
        int eccOvdmHashKeyNum = EccOvdmFactory.getHashNum(eccOvdmType);
        eccOvdmHashKeys = IntStream.range(0, eccOvdmHashKeyNum)
                .mapToObj(keyIndex -> {
                    byte[] key = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
                    secureRandom.nextBytes(key);
                    keysPayload.add(key);
                    return key;
                })
                .toArray(byte[][]::new);
        DataPacketHeader keysHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22OtPsuPtoDesc.PtoStep.SERVER_SEND_OVDM_KEYS.ordinal(), extraInfo,
                ownParty().getPartyId(), otherParty().getPartyId()
        );
        rpc.send(DataPacket.fromByteArrayList(keysHeader, keysPayload));
        stopWatch.stop();
        long keyTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Init Step 2/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), keyTime);

        stopWatch.start();
        DataPacketHeader pkHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22OtPsuPtoDesc.PtoStep.CLIENT_SEND_PK.ordinal(), extraInfo,
                otherParty().getPartyId(), ownParty().getPartyId()
        );
        List<byte[]> pkPayload = rpc.receive(pkHeader).getPayload();
        MpcAbortPreconditions.checkArgument(pkPayload.size() == 1);
        if (y != null) {
            // 清理之前的预计算结果
            ecc.destroyPrecompute(y);
        }
        y = ecc.decode(pkPayload.remove(0));
        // 预计算
        ecc.precompute(ecc.getG());
        ecc.precompute(y);
        stopWatch.stop();
        long pkTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Init Step 3/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), pkTime);

        initialized = true;
        info("{}{} Server Init end", ptoEndLogPrefix, getPtoDesc().getPtoName());
    }

    @Override
    public void psu(Set<ByteBuffer> serverElementSet, int clientElementSize, int elementByteLength)
            throws MpcAbortException {
        setPtoInput(serverElementSet, clientElementSize, elementByteLength);
        info("{}{} Server begin", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        stopWatch.start();
        // 接收密文header
        DataPacketHeader kemOvdmHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22OtPsuPtoDesc.PtoStep.CLIENT_SEND_OVDM_KEM.ordinal(), extraInfo,
                otherParty().getPartyId(), ownParty().getPartyId()
        );
        List<byte[]> kemOvdmPayload = rpc.receive(kemOvdmHeader).getPayload();
        // 接收密文payload
        DataPacketHeader ctOvdmHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22OtPsuPtoDesc.PtoStep.CLIENT_SEND_OVDM_CT.ordinal(), extraInfo,
                otherParty().getPartyId(), ownParty().getPartyId()
        );
        List<byte[]> ctOvdmPayload = rpc.receive(ctOvdmHeader).getPayload();
        handleOvdmPayload(kemOvdmPayload, ctOvdmPayload);
        stopWatch.stop();
        long ovdmTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 1/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), ovdmTime);

        stopWatch.start();
        BigInteger[] rs = ecc.randomZn(serverElementSize, secureRandom);
        pipelineReRand(rs);
        stopWatch.stop();
        long reRandTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 2/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), reRandTime);

        stopWatch.start();
        int randomnessByteLength = ecc.getN().toByteArray().length;

//        byte[] ZByte = new byte[] { 0x00, 0x01 };
//        ZByte = leftPadByteArray(ZByte,33);
//        BigInteger ZZ = new BigInteger(ZByte);
//        BigInteger N = ecc.getN();
//        byte[] Nbyte = N.toByteArray();
//        int length = Nbyte.length;
//        BigInteger NN = new BigInteger(Nbyte);
//        byte[] rs0 = rs[0].toByteArray();
//        byte[] pl = serverElementArrayList.get(0).array();
//
//        byte[] test = ByteBuffer.allocate(elementByteLength + randomnessByteLength)
//                .put(serverElementArrayList.get(0)).put(rs[0].toByteArray()).array();
        CotSenderOutput cotSenderOutput = coreCotSender.send(serverElementSize);
        Prg encPrg = PrgFactory.createInstance(envType, elementByteLength + randomnessByteLength);
        IntStream encIntStream = IntStream.range(0, serverElementSize);
        encIntStream = parallel ? encIntStream.parallel() : encIntStream;
        List<byte[]> encPayload = encIntStream
                .mapToObj(index -> {
                    byte[] key = cotSenderOutput.getR0(index);
                    key = crhf.hash(key);
                    byte[] ciphertext = encPrg.extendToBytes(key);
                    // # optimization, is this the right codes?
                    BytesUtils.xori(ciphertext, ByteBuffer.allocate(elementByteLength + randomnessByteLength)
                            .put(serverElementArrayList.get(index).array())
                            .put(leftPadByteArray(rs[index].toByteArray(), randomnessByteLength))
                            .array());
                    return ciphertext;
                })
                .collect(Collectors.toList());
        DataPacketHeader encHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22OtPsuPtoDesc.PtoStep.SERVER_SEND_ENC_ELEMENTS.ordinal(), extraInfo,
                ownParty().getPartyId(), otherParty().getPartyId()
        );
        rpc.send(DataPacket.fromByteArrayList(encHeader, encPayload));
        stopWatch.stop();
        long encTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 3/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), encTime);

        info("{}{} Server end", ptoEndLogPrefix, getPtoDesc().getPtoName());
    }

    private void handleOvdmPayload(List<byte[]> kemOvdmPayload, List<byte[]> ctOvdmPayload) throws MpcAbortException {
        int eccOvdmM = EccOvdmFactory.getM(eccOvdmType, clientElementSize);
        MpcAbortPreconditions.checkArgument(kemOvdmPayload.size() == eccOvdmM);
        MpcAbortPreconditions.checkArgument(ctOvdmPayload.size() == eccOvdmM);
        // 读取header和payload
        kemOvdmStorage = kemOvdmPayload.stream()
                .map(ecc::decode)
                .toArray(ECPoint[]::new);
        ctOvdmStorage = ctOvdmPayload.stream()
                .map(ecc::decode)
                .toArray(ECPoint[]::new);
        eccOvdm = EccOvdmFactory.createInstance(envType, eccOvdmType, ecc, clientElementSize, eccOvdmHashKeys);
    }

    private void pipelineReRand(BigInteger[] rs) {
        // 生成随机量
        // Pipeline过程，先执行整除倍，最后再循环一遍
        int pipelineTime = serverElementSize / pipeSize;
        int round;
        for (round = 0; round < pipelineTime; round++) {
            int offset = round * pipeSize;
            // 计算KEM
            IntStream kemIntStream = IntStream.range(0, pipeSize);
            kemIntStream = parallel ? kemIntStream.parallel() : kemIntStream;
            List<byte[]> reRandKemPayload = kemIntStream
                    .mapToObj(index -> {
                        ECPoint gr = ecc.multiply(ecc.getG(), rs[offset + index]);
                        return eccOvdm.decode(kemOvdmStorage, serverElementArrayList.get(offset + index)).add(gr);
                    })
                    .map(kem -> ecc.encode(kem, compressEncode))
                    .collect(Collectors.toList());
            // 发送KEM
            DataPacketHeader reRandKemHeader = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22OtPsuPtoDesc.PtoStep.SERVER_SEND_RERAND_KEM.ordinal(), extraInfo,
                    ownParty().getPartyId(), otherParty().getPartyId()
            );
            rpc.send(DataPacket.fromByteArrayList(reRandKemHeader, reRandKemPayload));
            // 计算密文
            IntStream ctIntStream = IntStream.range(0, pipeSize);
            ctIntStream = parallel ? ctIntStream.parallel() : ctIntStream;
            List<byte[]> reRandCtPayload = ctIntStream
                    .mapToObj(index -> {
                        ECPoint yr = ecc.multiply(y, rs[offset + index]);
                        return eccOvdm.decode(ctOvdmStorage, serverElementArrayList.get(offset + index)).add(yr);
                    })
                    .map(ct -> ecc.encode(ct, compressEncode))
                    .collect(Collectors.toList());
            DataPacketHeader reRandCtHeader = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22OtPsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT.ordinal(), extraInfo,
                    ownParty().getPartyId(), otherParty().getPartyId()
            );
            rpc.send(DataPacket.fromByteArrayList(reRandCtHeader, reRandCtPayload));
            extraInfo++;
        }
        int remain = serverElementSize - round * pipeSize;
        if (remain > 0) {
            int offset = round * pipeSize;
            // 计算KEM
            IntStream kemIntStream = IntStream.range(0, remain);
            kemIntStream = parallel ? kemIntStream.parallel() : kemIntStream;
            List<byte[]> reRandKemPayload = kemIntStream
                    .mapToObj(index -> {
                        ECPoint gr = ecc.multiply(ecc.getG(), rs[offset + index]);
                        return eccOvdm.decode(kemOvdmStorage, serverElementArrayList.get(offset + index)).add(gr);
                    })
                    .map(kem -> ecc.encode(kem, compressEncode))
                    .collect(Collectors.toList());
            // 发送KEM
            DataPacketHeader reRandKemHeader = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22OtPsuPtoDesc.PtoStep.SERVER_SEND_RERAND_KEM.ordinal(), extraInfo,
                    ownParty().getPartyId(), otherParty().getPartyId()
            );
            rpc.send(DataPacket.fromByteArrayList(reRandKemHeader, reRandKemPayload));
            // 计算密文
            IntStream ctIntStream = IntStream.range(0, remain);
            ctIntStream = parallel ? ctIntStream.parallel() : ctIntStream;
            List<byte[]> reRandCtPayload = ctIntStream
                    .mapToObj(index -> {
                        ECPoint yr = ecc.multiply(y, rs[offset + index]);
                        return eccOvdm.decode(ctOvdmStorage, serverElementArrayList.get(offset + index)).add(yr);
                    })
                    .map(ct -> ecc.encode(ct, compressEncode))
                    .collect(Collectors.toList());
            // 发送密文
            DataPacketHeader reRandCtHeader = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22OtPsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT.ordinal(), extraInfo,
                    ownParty().getPartyId(), otherParty().getPartyId()
            );
            rpc.send(DataPacket.fromByteArrayList(reRandCtHeader, reRandCtPayload));
            extraInfo++;
        }
    }

    public static byte[] leftPadByteArray(byte[] input, int totalSize) {
        // pad a byte array with 0 at the beginning.
        int size = input.length;
        assert(size  <= totalSize);
        if (size == totalSize) {
            return input;
        }

        byte[] padding = new byte[totalSize - size];
        for (int i = 0; i < padding.length; i++) {
            padding[i] = 0;
        }

        return ByteBuffer.allocate(totalSize)
                .put(padding)
                .put(input)
                .array();

    }
}

