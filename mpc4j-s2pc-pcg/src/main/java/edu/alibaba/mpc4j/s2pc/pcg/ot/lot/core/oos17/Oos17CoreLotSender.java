package edu.alibaba.mpc4j.s2pc.pcg.ot.lot.core.oos17;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacket;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.bitmatrix.trans.TransBitMatrix;
import edu.alibaba.mpc4j.common.tool.bitmatrix.trans.TransBitMatrixFactory;
import edu.alibaba.mpc4j.common.tool.crypto.crhf.Crhf;
import edu.alibaba.mpc4j.common.tool.crypto.crhf.CrhfFactory;
import edu.alibaba.mpc4j.common.tool.crypto.prf.Prf;
import edu.alibaba.mpc4j.common.tool.crypto.prf.PrfFactory;
import edu.alibaba.mpc4j.common.tool.crypto.prg.Prg;
import edu.alibaba.mpc4j.common.tool.crypto.prg.PrgFactory;
import edu.alibaba.mpc4j.common.tool.utils.BinaryUtils;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.s2pc.pcg.ot.lot.core.AbstractCoreLotSender;
import edu.alibaba.mpc4j.s2pc.pcg.ot.lot.core.CoreLotSenderOutput;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.core.CoreCotFactory;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.core.CoreCotReceiver;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.CotReceiverOutput;

import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

/**
 * OOS17-核2^l选1-OT协议发送方。
 *
 * @author Weiran Liu
 * @date 2022/6/8
 */
public class Oos17CoreLotSender extends AbstractCoreLotSender {
    /**
     * COT协议接收方
     */
    private final CoreCotReceiver coreCotReceiver;
    /**
     * 抗关联哈希函数
     */
    private final Crhf crhf;
    /**
     * COT协议接收方输出
     */
    private CotReceiverOutput cotReceiverOutput;
    /**
     * 随机预言机密钥
     */
    private byte[] randomOracleKey;
    /**
     * 扩展数量
     */
    private int extendNum;
    /**
     * 扩展字节数量
     */
    private int extendByteNum;
    /**
     * Q的转置矩阵
     */
    private TransBitMatrix qTransposeMatrix;

    public Oos17CoreLotSender(Rpc senderRpc, Party receiverParty, Oos17CoreLotConfig config) {
        super(Oos17CoreLotPtoDesc.getInstance(), senderRpc, receiverParty, config);
        coreCotReceiver = CoreCotFactory.createReceiver(senderRpc, receiverParty, config.getCoreCotConfig());
        coreCotReceiver.addLogLevel();
        crhf = CrhfFactory.createInstance(envType, CrhfFactory.CrhfType.MMO_SIGMA);
    }

    @Override
    public void setTaskId(long taskId) {
        super.setTaskId(taskId);
        coreCotReceiver.setTaskId(taskId);
    }

    @Override
    public void setParallel(boolean parallel) {
        super.setParallel(parallel);
        coreCotReceiver.setParallel(parallel);
    }

    @Override
    public void addLogLevel() {
        super.addLogLevel();
        coreCotReceiver.addLogLevel();
    }

    @Override
    public void init(int inputBitLength, byte[] delta, int maxNum) throws MpcAbortException {
        setInitInput(inputBitLength, delta, maxNum);
        init();
    }

    @Override
    public void init(int inputBitLength, int maxNum) throws MpcAbortException {
        setInitInput(inputBitLength, maxNum);
        init();
    }

    private void init() throws MpcAbortException {
        info("{}{} Send. Init begin", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        stopWatch.start();
        coreCotReceiver.init(outputBitLength);
        cotReceiverOutput = coreCotReceiver.receive(deltaBinary);
        stopWatch.stop();
        long initTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Send. Init Step 1/2 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), initTime);

        stopWatch.start();
        List<byte[]> randomOracleKeyPayload = new LinkedList<>();
        randomOracleKey = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
        secureRandom.nextBytes(randomOracleKey);
        randomOracleKeyPayload.add(randomOracleKey);
        DataPacketHeader randomOracleKeyHeader = new DataPacketHeader(
            taskId, getPtoDesc().getPtoId(), Oos17CoreLotPtoDesc.PtoStep.SENDER_SEND_RANDOM_ORACLE_KEY.ordinal(), extraInfo,
            ownParty().getPartyId(), otherParty().getPartyId()
        );
        rpc.send(DataPacket.fromByteArrayList(randomOracleKeyHeader, randomOracleKeyPayload));
        stopWatch.stop();
        long randomOracleTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Send. Init Step 2/2 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), randomOracleTime);

        initialized = true;
        info("{}{} Send. Init end", ptoEndLogPrefix, getPtoDesc().getPtoName());
    }

    @Override
    public CoreLotSenderOutput send(int num) throws MpcAbortException {
        setPtoInput(num);
        info("{}{} Send. begin", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        stopWatch.start();
        // Let m' = m + s
        extendNum = num + CommonConstants.STATS_BIT_LENGTH;
        extendByteNum = CommonUtils.getByteLength(extendNum);
        DataPacketHeader matrixHeader = new DataPacketHeader(
            taskId, ptoDesc.getPtoId(), Oos17CoreLotPtoDesc.PtoStep.RECEIVER_SEND_MATRIX.ordinal(), extraInfo,
            otherParty().getPartyId(), ownParty().getPartyId());
        List<byte[]> matrixPayload = rpc.receive(matrixHeader).getPayload();
        handleMatrixPayload(matrixPayload);
        stopWatch.stop();
        long keyGenTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Send. Step 1/2 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), keyGenTime);

        stopWatch.start();
        DataPacketHeader correlateCheckHeader = new DataPacketHeader(
            taskId, getPtoDesc().getPtoId(), Oos17CoreLotPtoDesc.PtoStep.RECEIVER_SEND_CHECK.ordinal(), extraInfo,
            otherParty().getPartyId(), ownParty().getPartyId()
        );
        List<byte[]> correlateCheckPayload = rpc.receive(correlateCheckHeader).getPayload();
        CoreLotSenderOutput senderOutput = handleCorrelateCheckPayload(correlateCheckPayload);
        qTransposeMatrix = null;
        stopWatch.stop();
        long checkTime = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Send. Step 2/2 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), checkTime);

        info("{}{} Send. end", ptoEndLogPrefix, getPtoDesc().getPtoName());
        return senderOutput;
    }

    private void handleMatrixPayload(List<byte[]> matrixPayload) throws MpcAbortException {
        MpcAbortPreconditions.checkArgument(matrixPayload.size() == outputBitLength);
        Prg prg = PrgFactory.createInstance(envType, extendByteNum);
        // 定义并设置矩阵Q
        TransBitMatrix qMatrix = TransBitMatrixFactory.createInstance(envType, extendNum, outputBitLength, parallel);
        byte[][] uArray = matrixPayload.toArray(new byte[0][]);
        // 矩阵生成流
        IntStream qMatrixIntStream = IntStream.range(0, outputBitLength);
        qMatrixIntStream = parallel ? qMatrixIntStream.parallel() : qMatrixIntStream;
        qMatrixIntStream.forEach(columnIndex -> {
            byte[] columnBytes = prg.extendToBytes(crhf.hash(cotReceiverOutput.getRb(columnIndex)));
            BytesUtils.reduceByteArray(columnBytes, extendNum);
            if (deltaBinary[columnIndex]) {
                BytesUtils.xori(columnBytes, uArray[columnIndex]);
            }
            qMatrix.setColumn(columnIndex, columnBytes);
        });
        // 矩阵转置，方便按行获取Q
        qTransposeMatrix = qMatrix.transpose();
    }

    private CoreLotSenderOutput handleCorrelateCheckPayload(List<byte[]> correlateCheckPayload) throws MpcAbortException {
        MpcAbortPreconditions.checkArgument(correlateCheckPayload.size() == 2 * CommonConstants.STATS_BIT_LENGTH);
        // 解包数组t和数组w
        byte[][] twArray = correlateCheckPayload.toArray(new byte[0][]);
        // 设置随机预言机
        Prf randomOracle = PrfFactory.createInstance(envType, byteNum);
        randomOracle.setKey(randomOracleKey);
        // q^(l) = Σ_{i ∈ [m]} t_i·x_i^(l) + t_{m + l}
        byte[][] expectQs = new byte[CommonConstants.STATS_BIT_LENGTH][];
        // C(w^(l)) ⊙ b ⊕ t^(l)
        byte[][] actualQs = new byte[CommonConstants.STATS_BIT_LENGTH][];
        IntStream correlateCheckIntStream = IntStream.range(0, CommonConstants.STATS_BIT_LENGTH);
        correlateCheckIntStream = parallel ? correlateCheckIntStream.parallel() : correlateCheckIntStream;
        correlateCheckIntStream.forEach(l -> {
            // 调用随机预言的输入是extraInfo || l
            byte[] indexMessage = ByteBuffer.allocate(Long.BYTES + Integer.BYTES)
                .putLong(extraInfo).putInt(l).array();
            // S samples random string (x_1^(l), ..., x_m^(l)) ∈ F_2^m
            byte[] xl = randomOracle.getBytes(indexMessage);
            BytesUtils.reduceByteArray(xl, num);
            boolean[] xlBinary = BinaryUtils.byteArrayToBinary(xl, num);
            expectQs[l] = new byte[outputByteLength];
            // Σ_{i ∈ [m]} t_i·x_i^(l)
            for (int i = 0; i < num; i++) {
                if (xlBinary[i]) {
                    BytesUtils.xori(expectQs[l], qTransposeMatrix.getColumn(i));
                }
            }
            // q^(l) = Σ_{i ∈ [m]} q_i·x_i^(l) + q_{m + l}
            BytesUtils.xori(expectQs[l], qTransposeMatrix.getColumn(num + l));
            // C(w^(l)) ⊙ b ⊕ t^(l)
            actualQs[l] = linearCoder.encode(
                BytesUtils.paddingByteArray(twArray[l * 2 + 1], linearCoder.getDatawordByteLength())
            );
            BytesUtils.andi(actualQs[l], delta);
            BytesUtils.xori(actualQs[l], twArray[l * 2]);
        });
        for (int l = 0; l < CommonConstants.STATS_BIT_LENGTH; l++) {
            MpcAbortPreconditions.checkArgument(Arrays.equals(expectQs[l], actualQs[l]));
        }
        byte[][] qsArray = IntStream.range(0, num)
            .mapToObj(qTransposeMatrix::getColumn)
            .toArray(byte[][]::new);
        return CoreLotSenderOutput.create(inputBitLength, delta, qsArray);
    }
}
