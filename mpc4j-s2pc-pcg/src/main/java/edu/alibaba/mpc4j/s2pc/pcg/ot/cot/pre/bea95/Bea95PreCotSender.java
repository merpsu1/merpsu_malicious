package edu.alibaba.mpc4j.s2pc.pcg.ot.cot.pre.bea95;

import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.stream.IntStream;

import edu.alibaba.mpc4j.common.rpc.MpcAbortException;
import edu.alibaba.mpc4j.common.rpc.MpcAbortPreconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;
import edu.alibaba.mpc4j.common.tool.utils.BinaryUtils;
import edu.alibaba.mpc4j.common.tool.utils.BytesUtils;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.CotSenderOutput;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.pre.AbstractPreCotSender;
import edu.alibaba.mpc4j.s2pc.pcg.ot.cot.pre.bea95.Bea95PreCotPtoDesc.PtoStep;

/**
 * Bea95-预计算COT协议发送方。
 *
 * @author Weiran Liu
 * @date 2022/01/14
 */
public class Bea95PreCotSender extends AbstractPreCotSender {

    public Bea95PreCotSender(Rpc senderRpc, Party receiverParty, Bea95PreCotConfig config) {
        super(Bea95PreCotPtoDesc.getInstance(), senderRpc, receiverParty, config);
    }

    @Override
    public void init() throws MpcAbortException {
        setInitInput();
        info("{}{} Send. Init begin", ptoBeginLogPrefix, getPtoDesc().getPtoName());

        initialized = true;
        info("{}{} Send. Init end", ptoEndLogPrefix, getPtoDesc().getPtoName());
    }

    @Override
    public CotSenderOutput send(CotSenderOutput preSenderOutput) throws MpcAbortException {
        info("{}{} Send. begin", ptoBeginLogPrefix, getPtoDesc().getPtoName());
        setPtoInput(preSenderOutput);

        stopWatch.start();
        DataPacketHeader xorHeader = new DataPacketHeader(
            taskId, getPtoDesc().getPtoId(), PtoStep.RECEIVER_SEND_XOR.ordinal(), extraInfo,
            otherParty().getPartyId(), ownParty().getPartyId()
        );
        List<byte[]> xorPayload = rpc.receive(xorHeader).getPayload();
        MpcAbortPreconditions.checkArgument(xorPayload.size() == 1);
        byte[] xors = xorPayload.remove(0);
        int offset = CommonUtils.getByteLength(preSenderOutput.getNum()) * Byte.SIZE - preSenderOutput.getNum();
        byte[][] r0Array = IntStream.range(0, preSenderOutput.getNum())
            // 如果纠正比特值，则更换一下位置
            .mapToObj(index -> BinaryUtils.getBoolean(xors, index + offset) ?
                preSenderOutput.getR1(index) : BytesUtils.clone(preSenderOutput.getR0(index)))
            .toArray(byte[][]::new);
        stopWatch.stop();
        long time = stopWatch.getTime(TimeUnit.MILLISECONDS);
        stopWatch.reset();
        info("{}{} Send. Step 1/1 ({}ms)", ptoStepLogPrefix, getPtoDesc().getPtoName(), time);

        info("{}{} Send. end", ptoEndLogPrefix, getPtoDesc().getPtoName());
        return CotSenderOutput.create(preSenderOutput.getDelta(), r0Array);
    }
}
