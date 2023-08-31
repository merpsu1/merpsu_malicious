package edu.alibaba.mpc4j.common.rpc.impl.memory;

import com.google.common.base.Preconditions;
import edu.alibaba.mpc4j.common.rpc.Party;
import edu.alibaba.mpc4j.common.rpc.Rpc;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacket;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketBuffer;
import edu.alibaba.mpc4j.common.rpc.utils.DataPacketHeader;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.stream.Collectors;

/**
 * 内存通信机制。
 *
 * @author Weiran Liu
 * @date 2021/12/09
 */
public class MemoryRpc implements Rpc {
    private static final Logger LOGGER = LoggerFactory.getLogger(MemoryRpc.class);
    /**
     * 参与方ID映射
     */
    private final HashMap<Integer, MemoryParty> partyIdHashMap;
    /**
     * 自己的参与方信息
     */
    private final MemoryParty ownParty;
    /**
     * 缓存区
     */
    private final DataPacketBuffer dataPacketBuffer;
    /**
     * 数据包数量
     */
    private long dataPacketNum;
    /**
     * 负载字节长度
     */
    private long payloadByteLength;
    /**
     * 发送字节长度
     */
    private long sendByteLength;
    /**
     * 延迟类型
     */
    private MemoryDelayType memoryDelayType;

    /**
     * 构建内存RPC。
     *
     * @param ownParty         自己的参与方信息。
     * @param partySet         参与方集合。
     * @param dataPacketBuffer 缓存区。
     */
    public MemoryRpc(MemoryParty ownParty, Set<MemoryParty> partySet, DataPacketBuffer dataPacketBuffer) {
        assert (dataPacketBuffer != null);
        // 所有参与方的数量必须大于1
        Preconditions.checkArgument(partySet.size() > 1, "Party set size must be greater than 1");
        // 参与方自身必须在所有参与方之中
        Preconditions.checkArgument(partySet.contains(ownParty), "Party set must contain own party");
        this.ownParty = ownParty;
        // 按照参与方索引值，将参与方信息插入到ID映射中
        partyIdHashMap = new HashMap<>();
        partySet.forEach(partySpec -> partyIdHashMap.put(partySpec.getPartyId(), partySpec));
        this.dataPacketBuffer = dataPacketBuffer;
        dataPacketNum = 0;
        payloadByteLength = 0;
        sendByteLength = 0;
        // 默认为无延时
        memoryDelayType = MemoryDelayType.NO_DELAY;
    }

    /**
     * 设置内存通信延迟时间。
     *
     * @param memoryDelayType 内存通信延迟时间。
     */
    public void setMemoryDelayType(MemoryDelayType memoryDelayType) {
        this.memoryDelayType = memoryDelayType;
    }

    @Override
    public Party ownParty() {
        return ownParty;
    }

    @Override
    public Set<Party> getPartySet() {
        return partyIdHashMap.keySet().stream().map(partyIdHashMap::get).collect(Collectors.toSet());
    }

    @Override
    public Party getParty(int partyId) {
        assert (partyIdHashMap.containsKey(partyId));
        return partyIdHashMap.get(partyId);
    }

    @Override
    public void connect() {
        int ownPartyId = ownParty.getPartyId();
        partyIdHashMap.keySet().stream().sorted().forEach(otherPartyId -> {
            if (otherPartyId != ownPartyId) {
                LOGGER.debug(
                    "{} successfully make connection with {}",
                    partyIdHashMap.get(ownPartyId), partyIdHashMap.get(otherPartyId)
                );
            }
        });
        LOGGER.info("{} connected", ownParty);
    }

    @Override
    public void send(DataPacket dataPacket) {
        DataPacketHeader header = dataPacket.getHeader();
        Preconditions.checkArgument(
            ownParty.getPartyId() == header.getSenderId(),
            "Sender ID must be %s", ownParty.getPartyId()
        );
        Preconditions.checkArgument(
            partyIdHashMap.containsKey(header.getReceiverId()),
            "Party set does not contain Receiver ID = %s", header.getReceiverId()
        );
        List<byte[]> payload = dataPacket.getPayload();
        // 先统计数据包大小，再发送数据包，否则可能会出现统计的时候数据包被其他线程修改，抛出并发异常
        dataPacketNum++;
        payloadByteLength += payload.stream().mapToInt(data -> data.length).sum();
        sendByteLength += payload.stream().mapToInt(data -> data.length).sum();
        // 往dataPacketBuffer中放置数据包
        dataPacketBuffer.put(dataPacket);
    }

    @Override
    public DataPacket receive(DataPacketHeader header) {
        Preconditions.checkArgument(
            ownParty.getPartyId() == header.getReceiverId(),
            "Receiver ID must be %s", ownParty.getPartyId()
        );
        Preconditions.checkArgument(
            partyIdHashMap.containsKey(header.getSenderId()),
            "Party set does not contain Sender ID = %s", header.getSenderId()
        );
        try {
            // 尝试从buffer中取出满足数据头的数据
            DataPacket dataPacket = dataPacketBuffer.take(header);
            // 统计数据包大小
            int dataPacketByteLength = dataPacket.getPayload().stream().mapToInt(data -> data.length).sum();
            // 网络延迟等待时间，虽然往返时间是来回的时间，但实际中还是要等待完整的RTT时间
            if (memoryDelayType.getRtt() > 0) {
                TimeUnit.MICROSECONDS.sleep((long)(memoryDelayType.getRtt() * 1000));
            }
            // 网络带宽等待时间，数据包总量按照比特计算，除以带宽（按照Mbps）计算，单位修正后得到的是需要等待的微秒值
            if (memoryDelayType.getBandWidth() > 0) {
                // 带宽等待时间为数据包总比特量除以总带宽量，单位为微妙。注意总带宽量要放大1.024^2倍
                long waitNanoSeconds = (long)((long)dataPacketByteLength * Byte.SIZE * 1000
                    / (memoryDelayType.getBandWidth() * 1.024 * 1.024));
                TimeUnit.NANOSECONDS.sleep(waitNanoSeconds);
            }
            return dataPacket;
        } catch (InterruptedException e) {
            // 线程终端，不需要等待，直接返回空
            return null;
        }
    }

    @Override
    public long getPayloadByteLength() {
        return payloadByteLength;
    }

    @Override
    public long getSendByteLength() {
        return sendByteLength;
    }

    @Override
    public long getSendDataPacketNum() {
        return dataPacketNum;
    }

    @Override
    public void reset() {
        payloadByteLength = 0;
        sendByteLength = 0;
        dataPacketNum = 0;
    }

    @Override
    public void synchronize() {
        // 对参与方进行排序，所有在自己之前的自己作为client、所有在自己之后的自己作为server
        int ownPartyId = ownParty.getPartyId();
        partyIdHashMap.keySet().stream().sorted().forEach(otherPartyId -> {
            if (otherPartyId < ownPartyId) {
                // 如果对方排序比自己小，则自己是client，需要给对方发送同步信息
                DataPacketHeader clientSynchronizeHeader = new DataPacketHeader(
                    Long.MAX_VALUE - ownPartyId, MemoryPtoDesc.getInstance().getPtoId(), MemoryPtoDesc.StepEnum.CLIENT_SYNCHRONIZE.ordinal(),
                    ownPartyId, otherPartyId
                );
                send(DataPacket.fromByteArrayList(clientSynchronizeHeader, new LinkedList<>()));
                // 获得对方的回复
                DataPacketHeader serverSynchronizeHeader = new DataPacketHeader(
                    Long.MAX_VALUE - otherPartyId, MemoryPtoDesc.getInstance().getPtoId(), MemoryPtoDesc.StepEnum.SERVER_SYNCHRONIZE.ordinal(),
                    otherPartyId, ownPartyId
                );
                receive(serverSynchronizeHeader);
            } else if (otherPartyId > ownPartyId) {
                // 如果对方排序比自己大，则自己是server
                DataPacketHeader clientSynchronizeHeader = new DataPacketHeader(
                    Long.MAX_VALUE - otherPartyId, MemoryPtoDesc.getInstance().getPtoId(), MemoryPtoDesc.StepEnum.CLIENT_SYNCHRONIZE.ordinal(),
                    otherPartyId, ownPartyId
                );
                receive(clientSynchronizeHeader);
                DataPacketHeader serverSynchronizeHeader = new DataPacketHeader(
                    Long.MAX_VALUE - ownPartyId, MemoryPtoDesc.getInstance().getPtoId(), MemoryPtoDesc.StepEnum.SERVER_SYNCHRONIZE.ordinal(),
                    ownPartyId, otherPartyId
                );
                send(DataPacket.fromByteArrayList(serverSynchronizeHeader, new LinkedList<>()));
            }
        });
        LOGGER.info("{} synchronized", ownParty);
    }

    @Override
    public void disconnect() {
        LOGGER.info("{} disconnected", ownParty);
    }
}
