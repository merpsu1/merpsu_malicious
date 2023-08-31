package edu.alibaba.mpc4j.s2pc.pso.psu.jsz22;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacket;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.crypto.hash.Hash;
import edu.alibaba.mpc4j.common.tool.crypto.hash.HashFactory;
import edu.alibaba.mpc4j.common.tool.hashbin.MaxBinSizeUtils;
import edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo.CuckooHashBin;
import edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo.CuckooHashBinFactory;
import edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo.CuckooHashBinFactory.CuckooHashBinType;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.s2pc.pso.oprf.OprfFactory;
import edu.alibaba.mpc4j.s2pc.pso.oprf.OprfReceiver;
import edu.alibaba.mpc4j.s2pc.pso.oprf.OprfReceiverOutput;
import edu.alibaba.mpc4j.s2pc.pso.osn.OsnFactory;
import edu.alibaba.mpc4j.s2pc.pso.osn.OsnPartyOutput;
import edu.alibaba.mpc4j.s2pc.pso.osn.OsnReceiver;
import edu.alibaba.mpc4j.s2pc.pso.osn.OsnSender;
import edu.alibaba.mpc4j.s2pc.pso.psu.AbstractPsuServer;
import edu.alibaba.mpc4j.s2pc.pso.psu.jsz22.Jsz22SfsPsuPtoDesc.PtoStep;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * JSZ22-SFS-PSU协议服务端。
 *
 * @author Weiran Liu
 * @date 2022/03/22
 */
public class Jsz22SfsPsuServer extends AbstractPsuServer {
    /**
     * 第一轮OSN发送方
     */
    private final OsnSender firstOsnSender;
    /**
     * OPRF接收方
     */
    private final OprfReceiver oprfReceiver;
    /**
     * 第二轮OSN接收方
     */
    private final OsnReceiver secondOsnReceiver;
    /**
     * 布谷鸟哈希类型
     */
    private final CuckooHashBinType cuckooHashBinType;
    /**
     * 布谷鸟哈希函数数量
     */
    private final int cuckooHashNum;
    /**
     * 布谷鸟哈希
     */
    private CuckooHashBin<ByteBuffer> cuckooHashBin;
    /**
     * 桶数量
     */
    private int binNum;
    /**
     * 最大桶大小
     */
    private int maxBinSize;
    /**
     * OPRF输出映射
     */
    private Hash oprfOutputMap;
    /**
     * π′
     */
    private int[] secondPi;
    /**
     * {a_1, ..., a_b}
     */
    private byte[][] aArray;
    /**
     * 服务端OPRF集合
     */
    private Set<ByteBuffer> serverOprfSet;
    /**
     * U_i
     */
    private boolean[] uArray;
    /**
     * π′的OSN协议输出
     */
    private OsnPartyOutput secondOsnReceiverOutput;

    public Jsz22SfsPsuServer(Rpc serverRpc, Party clientParty, Jsz22SfsPsuConfig config) {
        super(Jsz22SfsPsuPtoDesc.getInstance(), serverRpc, clientParty, config);
        firstOsnSender = OsnFactory.createSender(serverRpc, clientParty, config.getOsnConfig());
        firstOsnSender.addLogLevel();
        oprfReceiver = OprfFactory.createOprfReceiver(serverRpc, clientParty, config.getOprfConfig());
        oprfReceiver.addLogLevel();
        secondOsnReceiver = OsnFactory.createReceiver(serverRpc, clientParty, config.getOsnConfig());
        secondOsnReceiver.addLogLevel();
        cuckooHashBinType = config.getCuckooHashBinType();
        cuckooHashNum = CuckooHashBinFactory.getHashNum(cuckooHashBinType);
    }

    @Override
    public void setTaskId(long taskId) {
        super.setTaskId(taskId);
        byte[] taskIdBytes = ByteBuffer.allocate(Long.BYTES).putLong(taskId).array();
        firstOsnSender.setTaskId(taskIdPrf.getLong(1, taskIdBytes, Long.MAX_VALUE));
        oprfReceiver.setTaskId(taskIdPrf.getLong(2, taskIdBytes, Long.MAX_VALUE));
        secondOsnReceiver.setTaskId(taskIdPrf.getLong(3, taskIdBytes, Long.MAX_VALUE));
    }

    @Override
    public void setParallel(boolean parallel) {
        super.setParallel(parallel);
        firstOsnSender.setParallel(parallel);
        oprfReceiver.setParallel(parallel);
        secondOsnReceiver.setParallel(parallel);
    }

    @Override
    public void addLogLevel() {
        super.addLogLevel();
        firstOsnSender.addLogLevel();
        oprfReceiver.addLogLevel();
        secondOsnReceiver.addLogLevel();
    }

    @Override
    public void init(int maxServerElementSize, int maxClientElementSize) throws MpcAbortException {
        setInitInput(maxServerElementSize, maxClientElementSize);
        info("{}{} Server Init begin", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        stopWatch.start();
        int maxBinNum = CuckooHashBinFactory.getBinNum(cuckooHashBinType, maxServerElementSize);
        // 初始化各个子协议
        firstOsnSender.init(maxBinNum);
        oprfReceiver.init(maxBinNum);
        secondOsnReceiver.init(maxBinNum);
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Init Step 1/1 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), initTime);

        initialized = true;
        info("{}{} Server Init end", ptoEndLogPrefix, getPtoDesc().getPtoName());
    }

    @Override
    public void psu(Set<ByteBuffer> serverElementSet, int clientElementSize, int elementByteLength)
        throws MpcAbortException {
        setPtoInput(serverElementSet, clientElementSize, elementByteLength);
        info("{}{} Server begin", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        stopWatch.start();
        binNum = CuckooHashBinFactory.getBinNum(cuckooHashBinType, serverElementSize);
        maxBinSize = MaxBinSizeUtils.expectMaxBinSize(clientElementSize, binNum);
        // 初始化OPRF哈希
        int oprfOutputByteLength = Jsz22SfsPsuPtoDesc.getOprfByteLength(binNum, maxBinSize);
        oprfOutputMap = HashFactory.createInstance(envType, oprfOutputByteLength);
        // S inserts set X into the Cuckoo hash table, and fills empty bins with the dummy item d
        List<byte[]> cuckooHashKeyPayload = generateCuckooHashKeyPayload();
        DataPacketHeader cuckooHashKeyHeader = new DataPacketHeader(
            taskId, getPtoDesc().getPtoId(), PtoStep.SERVER_SEND_CUCKOO_HASH_KEYS.ordinal(), extraInfo,
            ownParty().getPartyId(), otherParty().getPartyId()
        );
        rpc.send(DataPacket.fromByteArrayList(cuckooHashKeyHeader, cuckooHashKeyPayload));
        // 服务端构造π′
        List<Integer> secondPiList = IntStream.range(0, binNum)
            .boxed()
            .collect(Collectors.toList());
        Collections.shuffle(secondPiList, secureRandom);
        secondPi = secondPiList.stream().mapToInt(permutation -> permutation).toArray();
        stopWatch.stop();
        long cuckooHashTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 1/6 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), cuckooHashTime);

        stopWatch.start();
        // 构建服务端元素向量(x_1, ..., x_m)
        Vector<byte[]> xVector = IntStream.range(0, binNum)
            .mapToObj(binIndex -> cuckooHashBin.getHashBinEntry(binIndex).getItemByteArray())
            .collect(Collectors.toCollection(Vector::new));
        cuckooHashBin = null;
        // S and R invoke the ideal functionality F_{PS}.
        // S acts as P_0 with input set X_S, obtains the shuffled shares {a_1, a_2, ... , a_b}.
        OsnPartyOutput firstOsnSenderOutput = firstOsnSender.osn(xVector, elementByteLength);
        aArray = IntStream.range(0, binNum)
            .mapToObj(firstOsnSenderOutput::getShare)
            .toArray(byte[][]::new);
        stopWatch.stop();
        long firstOsnTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 2/6 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), firstOsnTime);

        stopWatch.start();
        // S and R invoke the ideal functionality F_{mpOPRF}
        // S acts as P_0 with her shuffled shares {a_i}_{i ∈ [b]}, and obtains the outputs {F(k, a_i)}_{i ∈ [b]};
        OprfReceiverOutput oprfReceiverOutput = oprfReceiver.oprf(aArray);
        IntStream binIndexIntStream = IntStream.range(0, binNum);
        binIndexIntStream = parallel ? binIndexIntStream.parallel() : binIndexIntStream;
        serverOprfSet = binIndexIntStream
            .mapToObj(oprfReceiverOutput::getPrf)
            .map(oprf -> oprfOutputMap.digestToBytes(oprf))
            .map(ByteBuffer::wrap)
            .collect(Collectors.toSet());
        stopWatch.stop();
        long oprfTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 3/6 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), oprfTime);

        stopWatch.start();
        // S checks if F(k, a_i) is in I_i, if not, S sets U[i] = 1, otherwise, sets U[i] = 0;
        DataPacketHeader clientOprfHeader = new DataPacketHeader(
            taskId, getPtoDesc().getPtoId(), PtoStep.CLIENT_SEND_OPRFS.ordinal(), extraInfo,
            otherParty().getPartyId(), ownParty().getPartyId()
        );
        List<byte[]> clientOprfPayload = rpc.receive(clientOprfHeader).getPayload();
        handleClientOprfPayload(clientOprfPayload);
        stopWatch.stop();
        long checkTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 4/6 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), checkTime);

        stopWatch.start();
        // S and R invoke the ideal functionality F_{PS}.
        // S acts as P_1 with a random permutation π′, S obtains the shuffled share sets {s^1_1, s^1_2, ..., s^1_b}
        secondOsnReceiverOutput = secondOsnReceiver.osn(secondPi, elementByteLength);
        stopWatch.stop();
        long secondOsnTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 5/6 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), secondOsnTime);

        stopWatch.start();
        // For i ∈ [b]: If U[π′(i)] = 1, S sets z_i = a_{π′(i)} ⊕ s^1_i , otherwise, sets z_i = ⊥, then sends z_i to R;
        List<byte[]> zsPayload = generateZsPayload();
        DataPacketHeader zsHeader = new DataPacketHeader(
            taskId, getPtoDesc().getPtoId(), PtoStep.SERVER_SEND_ZS.ordinal(), extraInfo,
            ownParty().getPartyId(), otherParty().getPartyId()
        );
        rpc.send(DataPacket.fromByteArrayList(zsHeader, zsPayload));
        stopWatch.stop();
        long zsTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Server Step 6/6 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), zsTime);

        info("{}{} Server end", ptoEndLogPrefix, getPtoDesc().getPtoName());
    }

    private List<byte[]> generateCuckooHashKeyPayload() {
        // 设置布谷鸟哈希，如果发现不能构造成功，则可以重复构造
        boolean success = false;
        byte[][] cuckooHashKeys = null;
        while (!success) {
            try {
                cuckooHashKeys = IntStream.range(0, cuckooHashNum)
                    .mapToObj(hashIndex -> {
                        byte[] key = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
                        secureRandom.nextBytes(key);
                        return key;
                    })
                    .toArray(byte[][]::new);
                cuckooHashBin = CuckooHashBinFactory.createCuckooHashBin(
                    envType, cuckooHashBinType, serverElementSize, cuckooHashKeys
                );
                // 将客户端消息插入到CuckooHash中
                cuckooHashBin.insertItems(serverElementArrayList);
                if (cuckooHashBin.itemNumInStash() == 0) {
                    success = true;
                }
            } catch (ArithmeticException ignored) {
                // 如果插入不成功，就重新插入
            }
        }
        // 如果成功，则向布谷鸟哈希的空余位置插入空元素
        cuckooHashBin.insertPaddingItems(botElementByteBuffer);
        return Arrays.stream(cuckooHashKeys).collect(Collectors.toList());
    }

    private void handleClientOprfPayload(List<byte[]> clientOprfPayload) throws MpcAbortException {
        MpcAbortPreconditions.checkArgument(clientOprfPayload.size() == binNum * maxBinSize);
        byte[][] clientFlattenOprfs = clientOprfPayload.toArray(new byte[0][]);
        IntStream binIndexStream = IntStream.range(0, binNum);
        binIndexStream = parallel ? binIndexStream.parallel() : binIndexStream;
        // 这里与论文描述相反，能匹配上则设置为true
        uArray = new boolean[binNum];
        binIndexStream.forEach(binIndex -> {
            for (int itemIndex = 0; itemIndex < maxBinSize; itemIndex++) {
                if (serverOprfSet.contains(ByteBuffer.wrap(clientFlattenOprfs[binIndex * maxBinSize + itemIndex]))) {
                    uArray[binIndex] = true;
                    break;
                }
            }
        });
        serverOprfSet = null;
    }

    private List<byte[]> generateZsPayload() {
        IntStream binIndexStream = IntStream.range(0, binNum);
        binIndexStream = parallel ? binIndexStream.parallel() : binIndexStream;
        List<byte[]> zsPayload = binIndexStream
            .mapToObj(binIndex -> {
                // 这里与论文描述相反，uArray代表能匹配上
                if (!uArray[secondPi[binIndex]]) {
                    return BytesUtils.xor(aArray[secondPi[binIndex]], secondOsnReceiverOutput.getShare(binIndex));
                } else {
                    return new byte[0];
                }
            })
            .collect(Collectors.toList());
        uArray = null;
        aArray = null;
        secondOsnReceiverOutput = null;
        secondPi = null;

        return zsPayload;
    }
}
