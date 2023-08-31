package edu.alibaba.mpc4j.s2pc.pso.psu.merpsu22;

import com.google.common.base.Preconditions;
import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacket;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.crypto.crhf.Crhf;
import edu.alibaba.mpc4j.common.tool.crypto.crhf.CrhfFactory;
import edu.alibaba.mpc4j.common.tool.galoisfield.zn.Zn;
import edu.alibaba.mpc4j.common.tool.galoisfield.zn.ZnFactory;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.zn.ZnOvdmFactory;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.zn.ZnOvdm;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;
import edu.alibaba.mpc4j.common.tool.utils.ObjectUtils;
import edu.alibaba.mpc4j.crypto.phe.PheEngine;
import edu.alibaba.mpc4j.crypto.phe.PheFactory;
import edu.alibaba.mpc4j.crypto.phe.PheSecLevel;
import edu.alibaba.mpc4j.crypto.phe.impl.pai99.Pai99PhePublicKey;
import edu.alibaba.mpc4j.crypto.phe.params.PhePublicKey;
import edu.alibaba.mpc4j.s2pc.pso.psu.AbstractPsuServer;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
public class Merpsu22AhePsuServer extends AbstractPsuServer {
    /**
     * Zn-OVDM类型
     */
    private final ZnOvdmFactory.ZnOvdmType znOvdmType;
    /**
     * 流水线数量
     */
    private final int pipeSize;

    /**
     * AHE scheme
     */
    private final PheEngine pheEngine;
    /**
     * AHE scheme security level
     */
    private final PheSecLevel pheSecLevel;
    /**
     * Zn有限域
     */
    private Zn zn;
    /**
     * Z_{n^2}有限域
     */
    private Zn zn2;
//    /**
//     * 椭圆曲线
//     */
//    private final Ecc ecc;
    /**
     * 抗关联哈希函数
     */
    private final Crhf crhf;
    /**
     * ZN-OVDM哈希密钥
     */
    private byte[][] znOvdmHashKeys;
    /**
     * 公钥
     */
    private ZnOvdm<ByteBuffer> znOvdm;
    private PhePublicKey pk;
//    /**
//     * OVDM负载
//     */
//    private List<byte[]> ctOvdmPayload;

    private BigInteger[] ctOvdmStorage;

    public Merpsu22AhePsuServer(Rpc serverRpc, Party clientParty, Merpsu22AhePsuConfig config) {
        super(Merpsu22AhePsuPtoDesc.getInstance(), serverRpc, clientParty, config);
//        coreCotSender = CoreCotFactory.createSender(serverRpc, clientParty, config.getCoreCotConfig());
//        coreCotSender.addLogLevel();
        znOvdmType = config.getZnOvdmType();
//        eccOvdmType = config.getEccOvdmType();
//        compressEncode = config.getCompressEncode();
        pipeSize = config.getPipeSize();
//        ecc = EccFactory.createInstance(getEnvType());
        pheEngine = PheFactory.createInstance(PheFactory.PheType.PAI99, secureRandom);
        pheSecLevel = PheSecLevel.LAMBDA_128;
        crhf = CrhfFactory.createInstance(getEnvType(), CrhfFactory.CrhfType.MMO);
    }

    @Override
    public void init(int maxServerElementSize, int maxClientElementSize) throws MpcAbortException {
        setInitInput(maxServerElementSize, maxClientElementSize);
        info("{}{} Server Init begin********************", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        stopWatch.start();
        // 初始化各个子协议
//        byte[] delta = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
//        secureRandom.nextBytes(delta);
//        coreCotSender.init(delta, maxServerElementSize);
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Init Step 1/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), initTime);

        stopWatch.start();
        List<byte[]> keysPayload = new LinkedList<>();
        // 初始化OVDM密钥
        int znOvdmHashKeyNum = ZnOvdmFactory.getHashNum(znOvdmType);
        znOvdmHashKeys = IntStream.range(0, znOvdmHashKeyNum)
                .mapToObj(keyIndex -> {
                    byte[] key = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
                    secureRandom.nextBytes(key);
                    keysPayload.add(key);
                    return key;
                })
                .toArray(byte[][]::new);
        DataPacketHeader keysHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_OVDM_KEYS.ordinal(), extraInfo,
                ownParty().getPartyId(), otherParty().getPartyId()
        );
        rpc.send(DataPacket.fromByteArrayList(keysHeader, keysPayload));
        stopWatch.stop();
        long keyTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Init Step 2/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), keyTime);

        stopWatch.start();
        DataPacketHeader pkHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.CLIENT_SEND_PK.ordinal(), extraInfo,
                otherParty().getPartyId(), ownParty().getPartyId()
        );
        List<byte[]> pkPayload = rpc.receive(pkHeader).getPayload();
        MpcAbortPreconditions.checkArgument(pkPayload.size() == 5);
        pk = Pai99PhePublicKey.fromByteArrayList(pkPayload);
        zn = ZnFactory.createInstance(envType, pk.getModulus());
        zn2 = ZnFactory.createInstance(envType, pk.getCiphertextModulus());
        stopWatch.stop();
        long pkTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Init Step 3/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), pkTime);

        initialized = true;
        info("{}{} Server Init end", ptoEndLogPrefix, getPtoDesc().getPtoName());
    }

    public void psu(Set<ByteBuffer> serverElementSet, int clientElementSize, int elementByteLength)
            throws MpcAbortException {
        setPtoInput(serverElementSet, clientElementSize, elementByteLength);
        info("{}{} Server begin", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        stopWatch.start();
        // 接收密文payload
        DataPacketHeader ctOvdmHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.CLIENT_SEND_OVDM_CT.ordinal(), extraInfo,
                otherParty().getPartyId(), ownParty().getPartyId()
        );
        List<byte[]> ctOvdmPayload = rpc.receive(ctOvdmHeader).getPayload();
        handleOvdmPayload(ctOvdmPayload);
        stopWatch.stop();
        long ovdmTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 1/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), ovdmTime);

        stopWatch.start();
        pipelineReRand();
        stopWatch.stop();
        long reRandTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 2/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), reRandTime);

//        stopWatch.start();
//        int randomnessByteLength = ecc.getN().toByteArray().length;

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
//        CotSenderOutput cotSenderOutput = coreCotSender.send(serverElementSize);
//        Prg encPrg = PrgFactory.createInstance(envType, elementByteLength + randomnessByteLength);
//        IntStream encIntStream = IntStream.range(0, serverElementSize);
//        encIntStream = parallel ? encIntStream.parallel() : encIntStream;
//        List<byte[]> encPayload = encIntStream
//                .mapToObj(index -> {
//                    byte[] key = cotSenderOutput.getR0(index);
//                    key = crhf.hash(key);
//                    byte[] ciphertext = encPrg.extendToBytes(key);
//                    // # optimization, is this the right codes?
//                    BytesUtils.xori(ciphertext, ByteBuffer.allocate(elementByteLength + randomnessByteLength)
//                            .put(serverElementArrayList.get(index).array())
//                            .put(leftPadByteArray(rs[index].toByteArray(), randomnessByteLength))
//                            .array());
//                    return ciphertext;
//                })
//                .collect(Collectors.toList());
//        DataPacketHeader encHeader = new DataPacketHeader(
//                taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_ENC_ELEMENTS.ordinal(), extraInfo,
//                ownParty().getPartyId(), otherParty().getPartyId()
//        );
//        rpc.send(DataPacket.fromByteArrayList(encHeader, encPayload));
//        stopWatch.stop();
//        long encTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
//        stopWatch.reset();
//        info("{}{} Server Step 3/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), encTime);
//
//        info("{}{} Server end", ptoEndLogPrefix, getPtoDesc().getPtoName());
    }

    private void handleOvdmPayload(List<byte[]> ctOvdmPayload) throws MpcAbortException {
        int znOvdmM = ZnOvdmFactory.getM(znOvdmType, clientElementSize);
        MpcAbortPreconditions.checkArgument(ctOvdmPayload.size() == znOvdmM);
        // 读取header和payload
        ctOvdmStorage = ctOvdmPayload.stream()
                .map(BigInteger::new)
                .toArray(BigInteger[]::new);
        znOvdm = ZnOvdmFactory.createInstance(
                EnvType.STANDARD, znOvdmType, pk.getCiphertextModulus(), clientElementSize, znOvdmHashKeys);
    }

    private void pipelineReRand() {
        // Generate all randomnes used to re-randomize ciphertexts.
        BigInteger[] rs = IntStream.range(0, serverElementSize)
                .mapToObj(index -> zn.createNonZeroRandom(secureRandom)).toArray(BigInteger[]::new);
        // Pipeline过程，先执行整除倍，最后再循环一遍
        int pipelineTime = serverElementSize / pipeSize;
        int round;
        for (round = 0; round < pipelineTime; round++) {
            int offset = round * pipeSize;
            // calculate decoded ciphertexts
            IntStream decodeIntStream = IntStream.range(0, pipeSize);
            decodeIntStream = parallel ? decodeIntStream.parallel() : decodeIntStream;
            List<BigInteger> decodeCiphertexts = decodeIntStream
                    .mapToObj(index -> znOvdm.decode(ctOvdmStorage,serverElementArrayList.get(offset + index)))
                    .collect(Collectors.toList());

            // Generate rerandomize randomness
            IntStream randomnessIntStream = IntStream.range(0, pipeSize);
            randomnessIntStream = parallel ? randomnessIntStream.parallel() : randomnessIntStream;
            List<BigInteger[]> rr = randomnessIntStream
                    .mapToObj(index ->zn.createMultipleNonZeroRandom(rs[offset+index].toByteArray(),3))
                    .collect(Collectors.toList());

            // re-randomnize ct0.
            IntStream ct0IntStream = IntStream.range(0, pipeSize);
            ct0IntStream = parallel ? ct0IntStream.parallel() : ct0IntStream;
            List<byte[]> reRandCt0Payload = ct0IntStream
                    .mapToObj(index -> rawRerandomize(pk,decodeCiphertexts.get(index), rr.get(index)[0]).toByteArray())
                    .collect(Collectors.toList());
            // send ct0
            DataPacketHeader reRandCt0Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT0.ordinal(), extraInfo,
                    ownParty().getPartyId(), otherParty().getPartyId()
            );
            rpc.send(DataPacket.fromByteArrayList(reRandCt0Header, reRandCt0Payload));

            // compute and re-randomnize ct1.
            IntStream ct1IntStream = IntStream.range(0, pipeSize);
            ct1IntStream = parallel ? ct1IntStream.parallel() : ct1IntStream;
            List<byte[]> reRandCt1Payload = ct1IntStream
                    .mapToObj(index -> {
//                        FIXME: Bytebuffer to bytearray, is this correct?
                        BigInteger x = new BigInteger(serverElementArrayList.get(offset + index).array());
                        BigInteger ct1 = pheEngine.rawMultiply(pk, decodeCiphertexts.get(index),x);
                        return rawRerandomize(pk,ct1, rr.get(index)[1]).toByteArray();
                    }).collect(Collectors.toList());
            // send ct1
            DataPacketHeader reRandCt1Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT1.ordinal(), extraInfo,
                    ownParty().getPartyId(), otherParty().getPartyId()
            );
            rpc.send(DataPacket.fromByteArrayList(reRandCt1Header, reRandCt1Payload));

            // compute and re-randomnize ct2.
            IntStream ct2IntStream = IntStream.range(0, pipeSize);
            ct2IntStream = parallel ? ct2IntStream.parallel() : ct2IntStream;
            List<byte[]> reRandCt2Payload = ct2IntStream
                    .mapToObj(index -> {
                        BigInteger ct2 = pheEngine.rawMultiply(pk, decodeCiphertexts.get(index),rs[offset+index]);
                        return rawRerandomize(pk, ct2, rr.get(index)[2]).toByteArray();
                    }).collect(Collectors.toList());
            // send ct2
            DataPacketHeader reRandCt2Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT2.ordinal(), extraInfo,
                    ownParty().getPartyId(), otherParty().getPartyId()
            );
            rpc.send(DataPacket.fromByteArrayList(reRandCt2Header, reRandCt2Payload));
            extraInfo++;
        }
        int remain = serverElementSize - round * pipeSize;
        if (remain > 0) {
            int offset = round * pipeSize;
            IntStream decodeIntStream = IntStream.range(0, remain);
            decodeIntStream = parallel ? decodeIntStream.parallel() : decodeIntStream;
            List<BigInteger> decodeCiphertexts = decodeIntStream
                    .mapToObj(index -> znOvdm.decode(ctOvdmStorage,serverElementArrayList.get(offset + index)))
                    .collect(Collectors.toList());

            // Generate rerandomize randomness
            List<BigInteger[]> rr = IntStream.range(0, remain)
                    .mapToObj(index ->zn.createMultipleNonZeroRandom(rs[offset+index].toByteArray(),3))
                    .collect(Collectors.toList());
//            BigInteger xx = new BigInteger(ObjectUtils.objectToByteArray(serverElementArrayList.get(0)));
//            info("x"+xx.toString());
//            info("decodeCiphertexts"+decodeCiphertexts.get(0).toString());
//            info("r:"+ rs[0].toString());
//            info("r0:"+ rr.get(0)[0].toString());
//            info("r1:"+ rr.get(0)[1].toString());
//            info("r2:"+ rr.get(0)[2].toString());

            // re-randomnize ct0.
            IntStream ct0IntStream = IntStream.range(0, remain);
            ct0IntStream = parallel ? ct0IntStream.parallel() : ct0IntStream;
            List<byte[]> reRandCt0Payload = ct0IntStream
                    .mapToObj(index -> rawRerandomize(pk,decodeCiphertexts.get(index), rr.get(index)[0]).toByteArray())
                    .collect(Collectors.toList());
            // send ct0
            DataPacketHeader reRandCt0Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT0.ordinal(), extraInfo,
                    ownParty().getPartyId(), otherParty().getPartyId()
            );
            rpc.send(DataPacket.fromByteArrayList(reRandCt0Header, reRandCt0Payload));

            // compute and re-randomnize ct1.
            IntStream ct1IntStream = IntStream.range(0, remain);
            ct1IntStream = parallel ? ct1IntStream.parallel() : ct1IntStream;
            List<byte[]> reRandCt1Payload = ct1IntStream
                    .mapToObj(index -> {
//                        FIXME: Bytebuffer to bytearray, is this correct?
                        BigInteger x = new BigInteger(ObjectUtils.objectToByteArray(serverElementArrayList.get(offset + index)));
//                        BigInteger x = new BigInteger(serverElementArrayList.get(offset + index).array());
                        BigInteger ct1 = pheEngine.rawMultiply(pk, decodeCiphertexts.get(index),x);
                        return rawRerandomize(pk,ct1, rr.get(index)[1]).toByteArray();
                    }).collect(Collectors.toList());
            // send ct1
            DataPacketHeader reRandCt1Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT1.ordinal(), extraInfo,
                    ownParty().getPartyId(), otherParty().getPartyId()
            );
            rpc.send(DataPacket.fromByteArrayList(reRandCt1Header, reRandCt1Payload));

            // compute and re-randomnize ct2.
            IntStream ct2IntStream = IntStream.range(0, remain);
            ct2IntStream = parallel ? ct2IntStream.parallel() : ct2IntStream;
            List<byte[]> reRandCt2Payload = ct2IntStream
                    .mapToObj(index -> {
                        BigInteger ct2 = pheEngine.rawMultiply(pk, decodeCiphertexts.get(index),rs[offset+index]);
                        return rawRerandomize(pk, ct2, rr.get(index)[2]).toByteArray();
                    }).collect(Collectors.toList());
            // send ct2
            DataPacketHeader reRandCt2Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT2.ordinal(), extraInfo,
                    ownParty().getPartyId(), otherParty().getPartyId()
            );
            rpc.send(DataPacket.fromByteArrayList(reRandCt2Header, reRandCt2Payload));


            extraInfo++;
        }
    }

    public static BigInteger rawRerandomize(PhePublicKey pk, BigInteger ct, BigInteger r) {
        Preconditions.checkArgument(pk instanceof Pai99PhePublicKey);
        BigInteger modulus = pk.getModulus();
        BigInteger modulusSquared = pk.getCiphertextModulus();
        // 重随机化也使用DJN10优化方案，ct' = ct * r'^n mod n^2，其中r' ∈ Z_n
        return BigIntegerUtils.modPow(r, modulus, modulusSquared).multiply(ct).mod(modulusSquared);
    }



}
