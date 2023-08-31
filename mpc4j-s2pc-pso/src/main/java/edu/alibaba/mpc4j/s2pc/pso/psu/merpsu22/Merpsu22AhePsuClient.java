package edu.alibaba.mpc4j.s2pc.pso.psu.merpsu22;

import com.google.common.base.Preconditions;
import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacket;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.crypto.crhf.Crhf;
import edu.alibaba.mpc4j.common.tool.crypto.crhf.CrhfFactory;
import edu.alibaba.mpc4j.common.tool.galoisfield.zn.Zn;
import edu.alibaba.mpc4j.common.tool.galoisfield.zn.ZnFactory;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.zn.ZnOvdmFactory;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.zn.ZnOvdm;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.crypto.phe.PheEngine;
import edu.alibaba.mpc4j.crypto.phe.PheFactory;
import edu.alibaba.mpc4j.crypto.phe.PheSecLevel;
import edu.alibaba.mpc4j.crypto.phe.impl.pai99.Pai99PhePublicKey;
import edu.alibaba.mpc4j.crypto.phe.params.PheKeyGenParams;
import edu.alibaba.mpc4j.crypto.phe.params.PhePrivateKey;
import edu.alibaba.mpc4j.crypto.phe.params.PhePublicKey;
import edu.alibaba.mpc4j.s2pc.pso.psu.AbstractPsuClient;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;

public class Merpsu22AhePsuClient extends AbstractPsuClient {
//    /**
//     * 核COT协议接收方
//     */
//    private final CoreCotReceiver coreCotReceiver;
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
     * 抗关联哈希函数
     */
    private final Crhf crhf;
    /**
     * ZN-OVDM哈希密钥
     */
    private byte[][] znOvdmHashKeys;
//    /**
//     * 索引点
//     */
    private ZnOvdm<ByteBuffer> znOvdm;
//    private ECPoint s;
    /**
     * 私钥
     */
    private PhePrivateKey sk;
    /**
     * 公钥
     */
    private PhePublicKey pk;
    /**
     * OVDM负载
     */
    private List<byte[]> ctOvdmPayload;

    private BigInteger[] ctOvdmStorage;
//    /**
//     * 密文OVDM
//     */
//    private EccOvdm<ByteBuffer> eccOvdm;
//    /**
//     * OVDM密文存储
//     */
//    private ECPoint[] kemOvdmStorage;
//    /**
//     * OVDM负载存储
//     */
//    private ECPoint[] ctOvdmStorage;
//    private final ZnOvdmFactory.ZnOvdmType znOvdmType;
//    /**
//     * 是否使用压缩椭圆曲线编码
//     */

    public Merpsu22AhePsuClient(Rpc clientRpc, Party serverParty, Merpsu22AhePsuConfig config) {
        super(Merpsu22AhePsuPtoDesc.getInstance(), clientRpc, serverParty, config);
//        coreCotReceiver = CoreCotFactory.createReceiver(clientRpc, serverParty, config.getCoreCotConfig());
//        coreCotReceiver.addLogLevel();
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
    public void init(int maxClientElementSize, int maxServerElementSize) throws MpcAbortException {
        setInitInput(maxClientElementSize, maxServerElementSize);
        info("{}{} Client Init begin********************", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        stopWatch.start();
        // 初始化各个子协议
//        coreCotReceiver.init(maxServerElementSize);
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Client Init Step 1/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), initTime);

        stopWatch.start();
        // 计算公私钥
        boolean signed = false;
        int modulusBitLength = PheFactory.getModulusBitLength(PheFactory.PheType.PAI99, pheSecLevel);
        PheKeyGenParams keyGenParams = new PheKeyGenParams(pheSecLevel, signed, modulusBitLength);

//        byte[] seed = new byte[] { 0x00 };
//        SecureRandom secureRandom = new SecureRandom(seed);

        sk = pheEngine.keyGen(keyGenParams);
        pk = sk.getPublicKey();

        zn = ZnFactory.createInstance(envType, pk.getModulus());
//        zn2 = ZnFactory.createInstance(envType, pk.getCiphertextModulus());

        List<byte[]> pkPayload = pk.toByteArrayList();
        DataPacketHeader pkHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.CLIENT_SEND_PK.ordinal(), extraInfo,
                ownParty().getPartyId(), otherParty().getPartyId()
        );
        rpc.send(DataPacket.fromByteArrayList(pkHeader, pkPayload));
        stopWatch.stop();
        long pkTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Client Init Step 2/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), pkTime);

        stopWatch.start();
        DataPacketHeader keysHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_OVDM_KEYS.ordinal(), extraInfo,
                otherParty().getPartyId(), ownParty().getPartyId()
        );
        List<byte[]> keysPayload = rpc.receive(keysHeader).getPayload();
        int znOvdmHashKeyNum = ZnOvdmFactory.getHashNum(znOvdmType);
        MpcAbortPreconditions.checkArgument(keysPayload.size() == znOvdmHashKeyNum);
        znOvdmHashKeys = keysPayload.toArray(new byte[0][]);
        // 预计算
//        ecc.precompute(ecc.getG());
//        ecc.precompute(y);
        stopWatch.stop();
        long keyTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Client Init Step 3/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), keyTime);

        initialized = true;
        info("{}{} Client Init end", ptoEndLogPrefix, getPtoDesc().getPtoName());
    }

    @Override
    public Set<ByteBuffer> psu(Set<ByteBuffer> clientElementSet, int serverElementSize, int elementByteLength)
            throws MpcAbortException {
        setPtoInput(clientElementSet, serverElementSize, elementByteLength);
        info("{}{} Client begin", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        stopWatch.start();
        generateOvdmPayload();
        stopWatch.stop();
//        // 发送密文header
//        DataPacketHeader kemOvdmHeader = new DataPacketHeader(
//                taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.CLIENT_SEND_OVDM_KEM.ordinal(), extraInfo,
//                ownParty().getPartyId(), otherParty().getPartyId()
//        );
//        rpc.send(DataPacket.fromByteArrayList(kemOvdmHeader, kemOvdmPayload));
        // 发送密文payload
        DataPacketHeader ctOvdmHeader = new DataPacketHeader(
                taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.CLIENT_SEND_OVDM_CT.ordinal(), extraInfo,
                ownParty().getPartyId(), otherParty().getPartyId()
        );
        rpc.send(DataPacket.fromByteArrayList(ctOvdmHeader, ctOvdmPayload));
        long ovdmTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Client Step 1/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), ovdmTime);

        stopWatch.start();
        Set union = pipelineRecover();
        stopWatch.stop();
        long peqtTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Client Step 2/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), peqtTime);

//// Y \cup Z
//        IntStream resIntStream = IntStream.range(0, serverElementSize);
//        resIntStream = parallel ? resIntStream.parallel() : resIntStream;
//        Set<ByteBuffer> union = resIntStream
//                .mapToObj(index -> {
//                    if (peqtArray[index]) {
//                        return botElementByteBuffer;
//                    } else {
//                        return serverElementArrayList.get(index);
//                    }
//                })
//                .collect(Collectors.toSet());
        stopWatch.start();
        union.addAll(clientElementSet);
        union.remove(botElementByteBuffer);
        stopWatch.stop();
        long unionTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Client Step 3/3 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), unionTime);

        info("{}{} Client end", ptoEndLogPrefix, getPtoDesc().getPtoName());
        return union;
    }

    private void generateOvdmPayload() {
//        BigInteger exp = ecc.randomZn(secureRandom);
//        s = ecc.multiply(y, exp);

        znOvdm = ZnOvdmFactory.createInstance(
                EnvType.STANDARD, znOvdmType, pk.getCiphertextModulus(), clientElementSize, znOvdmHashKeys
        );
//        IntStream.range(0, clientElementSize).mapToObj(index -> randomZn(secureRandom)).toArray(BigInteger[]::new)
//
//        BigInteger[] rs = ecc.randomZn(clientElementSize, secureRandom);
        Map<ByteBuffer, BigInteger> payloadMap = IntStream.range(0, clientElementSize)
                .boxed()
                .collect(Collectors.toMap(
                        index -> clientElementArrayList.get(index),
                        index -> pheEngine.rawEncrypt(pk, BigInteger.ZERO)
                ));
        ctOvdmStorage = znOvdm.encode(payloadMap);
        // 打包
//        Stream<BigInteger> kemOvdmStream = Arrays.stream(kemZnOvdmStorage);
//        kemOvdmStream = parallel ? kemOvdmStream.parallel() : kemOvdmStream;
//        kemOvdmPayload = kemOvdmStream
//                .map(r -> ecc.multiply(ecc.getG(), r))
//                .map(kem -> ecc.encode(kem, compressEncode))
//                .collect(Collectors.toList());
        Stream<BigInteger> ctOvdmStream = Arrays.stream(ctOvdmStorage);
        ctOvdmStream = parallel ? ctOvdmStream.parallel() : ctOvdmStream;
        ctOvdmPayload = ctOvdmStream
                .map(BigInteger::toByteArray)
                .collect(Collectors.toList());
    }

    private Set<ByteBuffer> pipelineRecover() throws MpcAbortException {
//        FIXME:Using hashset correct?
        Set<ByteBuffer> setDiff = new HashSet<>();
        // Pipeline过程，先执行整除倍，最后再循环一遍
        int pipelineTime = serverElementSize / pipeSize;
        int round;
        for (round = 0; round < pipelineTime; round++) {
            // Receive Ct0s
            DataPacketHeader reRandCt0Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT0.ordinal(), extraInfo,
                    otherParty().getPartyId(), ownParty().getPartyId()
            );
            List<byte[]> reRandCt0Payload = rpc.receive(reRandCt0Header).getPayload();
            MpcAbortPreconditions.checkArgument(reRandCt0Payload.size() == pipeSize);

            // Decode Ct0s
            Stream<byte[]> reRandCt0Stream = reRandCt0Payload.stream();
            reRandCt0Stream = parallel ? reRandCt0Stream.parallel() : reRandCt0Stream;
            BigInteger[] reRandCt0Array = reRandCt0Stream
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);

            // Receive Ct1s
            DataPacketHeader reRandCt1Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT1.ordinal(), extraInfo,
                    otherParty().getPartyId(), ownParty().getPartyId()
            );
            List<byte[]> reRandCt1Payload = rpc.receive(reRandCt1Header).getPayload();
            MpcAbortPreconditions.checkArgument(reRandCt1Payload.size() == pipeSize);

            // Decode Ct1s
            Stream<byte[]> reRandCt1Stream = reRandCt1Payload.stream();
            reRandCt1Stream = parallel ? reRandCt1Stream.parallel() : reRandCt1Stream;
            BigInteger[] reRandCt1Array = reRandCt1Stream
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);

            // Receive Ct2s
            DataPacketHeader reRandCt2Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT2.ordinal(), extraInfo,
                    otherParty().getPartyId(), ownParty().getPartyId()
            );
            List<byte[]> reRandCt2Payload = rpc.receive(reRandCt2Header).getPayload();
            MpcAbortPreconditions.checkArgument(reRandCt2Payload.size() == pipeSize);

            // Decode Ct2s
            Stream<byte[]> reRandCt2Stream = reRandCt2Payload.stream();
            reRandCt2Stream = parallel ? reRandCt2Stream.parallel() : reRandCt2Stream;
            BigInteger[] reRandCt2Array = reRandCt2Stream
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);

            IntStream recIntStream = IntStream.range(0, pipeSize);
            recIntStream = parallel ? recIntStream.parallel() : recIntStream;
            Set<ByteBuffer> batch = recIntStream
                    .mapToObj(index -> recoverAndCheck(reRandCt0Array[index],reRandCt1Array[index],reRandCt2Array[index])
                    )
                    .collect(Collectors.toSet());
            setDiff.addAll(batch);
            setDiff.remove(botElementByteBuffer);
            extraInfo++;
        }
        int remain = serverElementSize - round * pipeSize;
        if (remain > 0) {
            // Receive Ct0s
            DataPacketHeader reRandCt0Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT0.ordinal(), extraInfo,
                    otherParty().getPartyId(), ownParty().getPartyId()
            );
            List<byte[]> reRandCt0Payload = rpc.receive(reRandCt0Header).getPayload();
            MpcAbortPreconditions.checkArgument(reRandCt0Payload.size() == remain);

            // Decode Ct0s
            Stream<byte[]> reRandCt0Stream = reRandCt0Payload.stream();
            reRandCt0Stream = parallel ? reRandCt0Stream.parallel() : reRandCt0Stream;
            BigInteger[] reRandCt0Array = reRandCt0Stream
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);

            // Receive Ct1s
            DataPacketHeader reRandCt1Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT1.ordinal(), extraInfo,
                    otherParty().getPartyId(), ownParty().getPartyId()
            );
            List<byte[]> reRandCt1Payload = rpc.receive(reRandCt1Header).getPayload();
            MpcAbortPreconditions.checkArgument(reRandCt1Payload.size() == remain);

            // Decode Ct1s
            Stream<byte[]> reRandCt1Stream = reRandCt1Payload.stream();
            reRandCt1Stream = parallel ? reRandCt1Stream.parallel() : reRandCt1Stream;
            BigInteger[] reRandCt1Array = reRandCt1Stream
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);

            // Receive Ct2s
            DataPacketHeader reRandCt2Header = new DataPacketHeader(
                    taskId, getPtoDesc().getPtoId(), Merpsu22AhePsuPtoDesc.PtoStep.SERVER_SEND_RERAND_CT2.ordinal(), extraInfo,
                    otherParty().getPartyId(), ownParty().getPartyId()
            );
            List<byte[]> reRandCt2Payload = rpc.receive(reRandCt2Header).getPayload();
            MpcAbortPreconditions.checkArgument(reRandCt2Payload.size() == remain);

            // Decode Ct2s
            Stream<byte[]> reRandCt2Stream = reRandCt2Payload.stream();
            reRandCt2Stream = parallel ? reRandCt2Stream.parallel() : reRandCt2Stream;
            BigInteger[] reRandCt2Array = reRandCt2Stream
                    .map(BigInteger::new)
                    .toArray(BigInteger[]::new);

            IntStream recIntStream = IntStream.range(0, remain);
            recIntStream = parallel ? recIntStream.parallel() : recIntStream;
            Set<ByteBuffer> batch = recIntStream
                    .mapToObj(index -> recoverAndCheck(reRandCt0Array[index],reRandCt1Array[index],reRandCt2Array[index])
                    )
                    .collect(Collectors.toSet());
            setDiff.addAll(batch);
            setDiff.remove(botElementByteBuffer);
            extraInfo++;
        }
        return setDiff;
    }

    private ByteBuffer recoverAndCheck(BigInteger ct0, BigInteger ct1, BigInteger ct2){
        BigInteger a = pheEngine.rawDecrypt(sk,ct0);
        BigInteger ax = pheEngine.rawDecrypt(sk,ct1);
        BigInteger ar = pheEngine.rawDecrypt(sk,ct2);

        if (a.equals(BigInteger.ZERO)){
            return botElementByteBuffer;
        }
        BigInteger a_inv = zn.inv(a);
        BigInteger x = zn.mul(a_inv, ax);
        BigInteger r = zn.mul(a_inv, ar);

        BigInteger decodedCt0 = znOvdm.decode(ctOvdmStorage,
                ByteBuffer.wrap(BytesUtils.clone(BytesUtils.paddingByteArray(x.toByteArray(), elementByteLength))));
//            multiplication 1 & 2
        BigInteger decodedCt1 = pheEngine.rawMultiply(pk, decodedCt0,x);
        BigInteger decodedCt2 = pheEngine.rawMultiply(pk, decodedCt0,r);
//            rerandomize 0 & 1 & 2
        BigInteger[] rr = zn.createMultipleNonZeroRandom(r.toByteArray(),3);

        decodedCt0 = rawRerandomize(pk,decodedCt0 , rr[0]);
        decodedCt1 = rawRerandomize(pk,decodedCt1 , rr[1]);
        decodedCt2 = rawRerandomize(pk,decodedCt2 , rr[2]);

        if (ct0.equals(decodedCt0) && ct1.equals(decodedCt1) && ct2.equals(decodedCt2)){
            return ByteBuffer.wrap(BytesUtils.clone(BytesUtils.paddingByteArray(x.toByteArray(), elementByteLength)));
        }
        else{
            return botElementByteBuffer;
        }
    }

    public static BigInteger rawRerandomize(PhePublicKey pk, BigInteger ct, BigInteger r) {
        Preconditions.checkArgument(pk instanceof Pai99PhePublicKey);
        BigInteger modulus = pk.getModulus();
        BigInteger modulusSquared = pk.getCiphertextModulus();
        // 重随机化也使用DJN10优化方案，ct' = ct * r'^n mod n^2，其中r' ∈ Z_n
        return BigIntegerUtils.modPow(r, modulus, modulusSquared).multiply(ct).mod(modulusSquared);
    }
//    private void pipelineReRandCheck(ArrayList<ByteBuffer> serverElementArrayList, List<byte[]> rs) {
//        // 生成随机量
//        // Pipeline过程，先执行整除倍，最后再循环一遍
//        int pipelineTime = serverElementSize / pipeSize;
//        int round;
//        for (round = 0; round < pipelineTime; round++) {
//            List<byte[]> reRandKemPayload = reRandKemPayloadList.get(round);
//            List<byte[]> reRandCtPayload = reRandCtPayloadList.get(round);
//
//            int offset = round * pipeSize;
//            // 计算KEM
//            IntStream kemIntStream = IntStream.range(0, pipeSize);
//            kemIntStream = parallel ? kemIntStream.parallel() : kemIntStream;
//
//            List<byte[]> reRandKemPayload2 = kemIntStream
//                    .mapToObj(index -> {
//                        if (peqtArray[offset + index]){
//                            return new byte[0];
//                        }
//                        else{
//                            ECPoint gr = ecc.multiply(ecc.getG(), new BigInteger(rs.get(offset + index)));
//                            return ecc.encode(eccOvdm.decode(kemOvdmStorage,
//                                    serverElementArrayList.get(offset + index)).add(gr), compressEncode);
//                        }
//                    })
//                    .collect(Collectors.toList());
//            // 计算密文
//            IntStream ctIntStream = IntStream.range(0, pipeSize);
//            ctIntStream = parallel ? ctIntStream.parallel() : ctIntStream;
//            List<byte[]> reRandCtPayload2 = ctIntStream
//                    .mapToObj(index -> {
//                        if (peqtArray[offset + index]){
//                            return new byte[0];
//                        }
//                        else {
//                            ECPoint yr = ecc.multiply(y, new BigInteger(rs.get(offset + index)));
//                            return ecc.encode(eccOvdm.decode(ctOvdmStorage,
//                                    serverElementArrayList.get(offset + index)).add(yr), compressEncode);
//                        }
//                    })
//                    .collect(Collectors.toList());
//            // Check for consistency, update peqt array.
//            IntStream chkIntStream = IntStream.range(0, pipeSize);
//            chkIntStream = parallel ? chkIntStream.parallel() : chkIntStream;
//            chkIntStream.forEach(index -> {
//                if (peqtArray[offset + index] == false){
//                    boolean checkKem = !Arrays.equals(reRandKemPayload.get(index),reRandKemPayload2.get(index));
//                    boolean checkCt = !Arrays.equals(reRandCtPayload.get(index),reRandCtPayload2.get(index));
//                    peqtArray[offset + index] = (checkKem || checkCt);
//                }
//            });
//            extraInfo++;
//        }
//        int remain = serverElementSize - round * pipeSize;
//        if (remain > 0) {
//            List<byte[]> reRandKemPayload = reRandKemPayloadList.get(round);
//            List<byte[]> reRandCtPayload = reRandCtPayloadList.get(round);
//            int offset = round * pipeSize;
//            // 计算KEM
//            IntStream kemIntStream = IntStream.range(0, remain);
//            kemIntStream = parallel ? kemIntStream.parallel() : kemIntStream;
//
//            List<byte[]> reRandKemPayload2 = kemIntStream
//                    .mapToObj(index -> {
//                        if (peqtArray[offset + index]){
//                            return new byte[0];
//                        }
//                        else{
//                            ECPoint gr = ecc.multiply(ecc.getG(), new BigInteger(rs.get(offset + index)));
//                            return ecc.encode(eccOvdm.decode(kemOvdmStorage,
//                                    serverElementArrayList.get(offset + index)).add(gr), compressEncode);
//                        }
//                    })
//                    .collect(Collectors.toList());
//            // 计算密文
//            IntStream ctIntStream = IntStream.range(0, remain);
//            ctIntStream = parallel ? ctIntStream.parallel() : ctIntStream;
//            List<byte[]> reRandCtPayload2 = ctIntStream
//                    .mapToObj(index -> {
//                        if (peqtArray[offset + index]){
//                            return new byte[0];
//                        }
//                        else {
//                            ECPoint yr = ecc.multiply(y, new BigInteger(rs.get(offset + index)));
//                            return ecc.encode(eccOvdm.decode(ctOvdmStorage,
//                                    serverElementArrayList.get(offset + index)).add(yr), compressEncode);
//                        }
//                    })
//                    .collect(Collectors.toList());
//            // Check for consistency, update peqt array.
//            IntStream chkIntStream = IntStream.range(0, remain);
//            chkIntStream = parallel ? chkIntStream.parallel() : chkIntStream;
//            chkIntStream.forEach(index -> {
//                if (peqtArray[offset + index] == false){
//                    boolean checkKem = !Arrays.equals(reRandKemPayload.get(index),reRandKemPayload2.get(index));
//                    boolean checkCt = !Arrays.equals(reRandCtPayload.get(index),reRandCtPayload2.get(index));
//                    peqtArray[offset + index] = (checkKem || checkCt);
////                            reRandKemPayload.get(offset + index)!=reRandKemPayload2.get(offset + index)
////                                    || reRandCtPayload.get(offset + index)!=reRandCtPayload2.get(offset + index));
//                }
//            });
//            extraInfo++;
//        }
//    }


}
