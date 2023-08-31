package edu.alibaba.mpc4j.common.tool.okve.ovdm.zn;

import cc.redberry.rings.linear.LinearSolver.SystemInfo;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.crypto.prf.Prf;
import edu.alibaba.mpc4j.common.tool.crypto.prf.PrfFactory;
import edu.alibaba.mpc4j.common.tool.galoisfield.zn.ZnMaxLisFinder;
import edu.alibaba.mpc4j.common.tool.okve.cuckootable.CuckooTableSingletonTcFinder;
import edu.alibaba.mpc4j.common.tool.okve.cuckootable.H3CuckooTable;
import edu.alibaba.mpc4j.common.tool.okve.ovdm.zn.ZnOvdmFactory.ZnOvdmType;
import edu.alibaba.mpc4j.common.tool.utils.*;

import java.math.BigInteger;
import java.util.*;
import java.util.function.Function;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * 3哈希-两核Zn-OVDM实现。
 *
 * @author Weiran Liu
 * @date 2021/10/02
 */
class H3TcGctZnOvdm<T> extends AbstractZnOvdm<T> {
    /**
     * 3哈希-两核乱码布谷鸟表需要4个哈希函数：3个布谷鸟哈希的哈希函数，1个右侧哈希函数
     */
    static final int HASH_NUM = 4;
    /**
     * 3哈希-两核乱码布谷鸟表左侧编码放大系数
     */
    private static final double LEFT_EPSILON = 1.3;
    /**
     * 3哈希-两核乱码布谷鸟表右侧编码放大系数
     */
    private static final double RIGHT_EPSILON = 0.5;
    /**
     * 左侧编码比特长度，等于1.3 * n，向上取整为Byte.SIZE的整数倍
     */
    private final int lm;
    /**
     * 右侧编码比特长度，等于0.5 * log(n) + λ，向上取整为Byte.SIZE的整数倍
     */
    private final int rm;
    /**
     * 布谷鸟哈希的第1个哈希函数
     */
    private final Prf h1;
    /**
     * 布谷鸟哈希的第2个哈希函数
     */
    private final Prf h2;
    /**
     * 布谷鸟哈希的第3个哈希函数
     */
    private final Prf h3;
    /**
     * 用于计算右侧r(x)的哈希函数
     */
    private final Prf hr;
    /**
     * 数据到h1的映射表
     */
    private Map<T, Integer> dataH1Map;
    /**
     * 数据到h2的映射表
     */
    private Map<T, Integer> dataH2Map;
    /**
     * 数据到h3的映射表
     */
    private Map<T, Integer> dataH3Map;
    /**
     * 数据到hr的映射表
     */
    private Map<T, boolean[]> dataHrMap;

    H3TcGctZnOvdm(EnvType envType, BigInteger ciphertextModulus, int n, byte[][] keys) {
        super(envType, ciphertextModulus, n, getLm(n) + getRm(n));
        lm = getLm(n);
        rm = getRm(n);
        h1 = PrfFactory.createInstance(envType, Integer.BYTES);
        h1.setKey(keys[0]);
        h2 = PrfFactory.createInstance(envType, Integer.BYTES);
        h2.setKey(keys[1]);
        h3 = PrfFactory.createInstance(envType, Integer.BYTES);
        h3.setKey(keys[2]);
        hr = PrfFactory.createInstance(envType, rm / Byte.SIZE);
        hr.setKey(keys[3]);
    }

    /**
     * 返回不同的哈希值。
     *
     * @param message 消息。
     * @return 不同的哈希值。
     */
    private int[] hashDistinctValues(byte[] message) {
        int[] hValues = new int[3];
        hValues[0] = h1.getInteger(0, message, lm);
        // 得到与h1Value取值不同的h2Value
        int h2Index = 0;
        do {
            hValues[1] = h2.getInteger(h2Index, message, lm);
            h2Index++;
        } while (hValues[1] == hValues[0]);
        // 得到与h1Value和h2Value取值不同的h3Value
        int h3Index = 0;
        do {
            hValues[2] = h3.getInteger(h3Index, message, lm);
            h3Index++;
        } while (hValues[2] == hValues[0] || hValues[2] == hValues[1]);

        return hValues;
    }

    @Override
    public BigInteger decode(BigInteger[] storage, T key) {
        assert storage.length == getM();
        byte[] keyBytes = ObjectUtils.objectToByteArray(key);
        int[] hValues = hashDistinctValues(keyBytes);
        boolean[] rxBinary = BinaryUtils.byteArrayToBinary(hr.getBytes(keyBytes));
        BigInteger value = BigInteger.ZERO;
        // 三个哈希结果一定不同，计算3次求和
        value = zn.add(value, storage[hValues[0]]);
        value = zn.add(value, storage[hValues[1]]);
        value = zn.add(value, storage[hValues[2]]);
        for (int rmIndex = 0; rmIndex < rm; rmIndex++) {
            if (rxBinary[rmIndex]) {
                value = zn.add(value, storage[lm + rmIndex]);
            }
        }
        return value;
    }

    @Override
    public ZnOvdmType getZnOvdmType() {
        return ZnOvdmType.H3_SINGLETON_GCT;
    }

    @Override
    public BigInteger[] encode(Map<T, BigInteger> keyValueMap) throws ArithmeticException {
        assert keyValueMap.size() <= n;
        // 构造数据到哈希值的查找表
        Set<T> keySet = keyValueMap.keySet();
        dataH1Map = new HashMap<>(keySet.size());
        dataH2Map = new HashMap<>(keySet.size());
        dataH3Map = new HashMap<>(keySet.size());
        dataHrMap = new HashMap<>(keySet.size());
        for (T key : keySet) {
            byte[] keyBytes = ObjectUtils.objectToByteArray(key);
            int[] hValues = hashDistinctValues(keyBytes);
            dataH1Map.put(key, hValues[0]);
            dataH2Map.put(key, hValues[1]);
            dataH3Map.put(key, hValues[2]);
            dataHrMap.put(key, BinaryUtils.byteArrayToBinary(hr.getBytes(keyBytes)));
        }
        // 生成3哈希-布谷鸟图
        H3CuckooTable<T> h3CuckooTable = generateCuckooTable(keyValueMap);
        // 找到2-core图
        CuckooTableSingletonTcFinder<T> singletonFinder = new CuckooTableSingletonTcFinder<>();
        singletonFinder.findTwoCore(h3CuckooTable);
        // 根据2-core图的所有数据和所有边构造矩阵
        Set<T> coreDataSet = singletonFinder.getRemainedDataSet();
        // 生成矩阵，矩阵中包含右侧的全部解，以及2-core中的全部解
        BigInteger[] storage = generateStorage(keyValueMap, coreDataSet);
        // 将矩阵拆分为L || R
        BigInteger[] leftStorage = new BigInteger[lm];
        BigInteger[] rightStorage = new BigInteger[rm];
        System.arraycopy(storage, 0, leftStorage, 0, lm);
        System.arraycopy(storage, lm, rightStorage, 0, rm);
        // 从栈中依次弹出数据，为相应节点赋值
        Stack<T> removedDataStack = singletonFinder.getRemovedDataStack();
        Stack<Integer[]> removedDataVerticesStack = singletonFinder.getRemovedDataVertices();
        // 先计算右侧内积结果
        Map<T, BigInteger> removedDataInnerProductMap = removedDataStack.stream()
                .collect(Collectors.toMap(Function.identity(), removedData -> {
                    boolean[] rx = dataHrMap.get(removedData);
                    BigInteger rightInnerProduct = zn.innerProduct(rightStorage, rx);
                    BigInteger value = keyValueMap.get(removedData);
                    return zn.sub(value, rightInnerProduct);
                }));
        while (!removedDataStack.empty()) {
            T removedData = removedDataStack.pop();
            Integer[] removedDataVertices = removedDataVerticesStack.pop();
            int vertex0 = removedDataVertices[0];
            int vertex1 = removedDataVertices[1];
            int vertex2 = removedDataVertices[2];
            BigInteger innerProduct = removedDataInnerProductMap.get(removedData);
            // 三个顶点一定不相同
            fullDistinctVertices(leftStorage, innerProduct, vertex0, vertex1, vertex2, removedData);
        }
        // 左侧矩阵补充随机数
        for (int vertex = 0; vertex < lm; vertex++) {
            if (leftStorage[vertex] == null) {
                leftStorage[vertex] = zn.createNonZeroRandom(secureRandom);
            }
        }
        // 更新矩阵
        System.arraycopy(leftStorage, 0, storage, 0, leftStorage.length);
        // 不应该再有没有更新的矩阵行了
        for (BigInteger row : storage) {
            assert row != null;
        }
        return storage;
    }

    private void fullDistinctVertices(BigInteger[] leftMatrix, BigInteger innerProduct,
                                      int vertex0, int vertex1, int vertex2, T data) {
        if (leftMatrix[vertex0] == null && leftMatrix[vertex1] == null && leftMatrix[vertex2] == null) {
            // 0、1、2都为空
            leftMatrix[vertex0] = zn.createNonZeroRandom(secureRandom);
            leftMatrix[vertex1] = zn.createNonZeroRandom(secureRandom);
            leftMatrix[vertex2] = zn.sub(zn.sub(innerProduct, leftMatrix[vertex0]), leftMatrix[vertex1]);
        } else if (leftMatrix[vertex0] == null && leftMatrix[vertex1] == null) {
            // 0、1为空
            leftMatrix[vertex0] = zn.createNonZeroRandom(secureRandom);
            leftMatrix[vertex1] = zn.sub(zn.sub(innerProduct, leftMatrix[vertex0]), leftMatrix[vertex2]);
        } else if (leftMatrix[vertex0] == null && leftMatrix[vertex2] == null) {
            // 0、2为空
            leftMatrix[vertex0] = zn.createNonZeroRandom(secureRandom);
            leftMatrix[vertex2] = zn.sub(zn.sub(innerProduct, leftMatrix[vertex0]), leftMatrix[vertex1]);
        } else if (leftMatrix[vertex1] == null && leftMatrix[vertex2] == null) {
            // 1、2为空
            leftMatrix[vertex1] = zn.createNonZeroRandom(secureRandom);
            leftMatrix[vertex2] = zn.sub(zn.sub(innerProduct, leftMatrix[vertex0]), leftMatrix[vertex1]);
        } else if (leftMatrix[vertex0] == null) {
            // 0为空
            leftMatrix[vertex0] = zn.sub(zn.sub(innerProduct, leftMatrix[vertex1]), leftMatrix[vertex2]);
        } else if (leftMatrix[vertex1] == null) {
            // 1为空
            leftMatrix[vertex1] = zn.sub(zn.sub(innerProduct, leftMatrix[vertex0]), leftMatrix[vertex2]);
        } else if (leftMatrix[vertex2] == null) {
            // 2为空
            leftMatrix[vertex2] = zn.sub(zn.sub(innerProduct, leftMatrix[vertex0]), leftMatrix[vertex1]);
        } else {
            // 三个都不为空，不可能出现这种情况
            throw new IllegalStateException(data + "的顶点(" + vertex0 + ", " + vertex1 + ", " + vertex2 + ")均不为空");
        }
    }

    private BigInteger[] generateStorage(Map<T, BigInteger> keyValueMap, Set<T> coreDataSet) {
        // 初始化OVDM存储器，所有位置设置为空
        BigInteger[] storage = new BigInteger[m];
        // Let d˜ = |R| and abort if d˜ > d + λ
        int dTilde = coreDataSet.size();
        // 如果没有2-core边，则补充的边都设置为随机数
        if (dTilde == 0) {
            IntStream.range(lm, lm + rm).forEach(index -> storage[index] = zn.createNonZeroRandom(secureRandom));
            return storage;
        }
        if (dTilde > rm) {
            throw new ArithmeticException("|d˜| = " + dTilde + "，d + λ + " + rm + "，线性系统无解");
        }
        // Let M˜' ∈ {0, 1}^{d˜ × (d + λ)} be the sub-matrix of M˜ obtained by taking the row indexed by R.
        BigInteger[][] tildePrimeMatrix = new BigInteger[rm][dTilde];
        int tildePrimeMatrixRowIndex = 0;
        for (T data : coreDataSet) {
            boolean[] rxBinary = dataHrMap.get(data);
            for (int rmIndex = 0; rmIndex < rm; rmIndex++) {
                tildePrimeMatrix[rmIndex][tildePrimeMatrixRowIndex]
                        = rxBinary[rmIndex] ? BigInteger.ONE : BigInteger.ZERO;
            }
            tildePrimeMatrixRowIndex++;
        }
        // Otherwise, let M˜* be one such matrix and C ⊂ [d + λ] index the corresponding columns of M˜.
        ZnMaxLisFinder znMaxLisFinder = new ZnMaxLisFinder(zn.getN(), tildePrimeMatrix);
        Set<Integer> setC = znMaxLisFinder.getLisRows();
        BigInteger[][] tildeStarMatrix = new BigInteger[dTilde][setC.size()];
        int tildeStarMatrixRowIndex = 0;
        for (T data : coreDataSet) {
            boolean[] rxBinary = dataHrMap.get(data);
            int rmIndex = 0;
            for (Integer r : setC) {
                tildeStarMatrix[tildeStarMatrixRowIndex][rmIndex] = rxBinary[r] ? BigInteger.ONE : BigInteger.ZERO;
                rmIndex++;
            }
            tildeStarMatrixRowIndex++;
        }
        // Let C' = {j | i \in R, M'_{i, j} = 1} ∪ ([d + λ] \ C + m')
        Set<Integer> setPrimeC = new HashSet<>(dTilde * 2 + rm / 2);
        for (T data : coreDataSet) {
            setPrimeC.add(dataH1Map.get(data));
            setPrimeC.add(dataH2Map.get(data));
            setPrimeC.add(dataH3Map.get(data));
        }
        for (int rmIndex = 0; rmIndex < rm; rmIndex++) {
            if (!setC.contains(rmIndex)) {
                setPrimeC.add(lm + rmIndex);
            }
        }
        // For i ∈ C' assign P_i ∈ G
        for (Integer primeIndexC : setPrimeC) {
            storage[primeIndexC] = zn.createNonZeroRandom(secureRandom);
        }
        // For i ∈ R, define v'_i = v_i - (MP), where P_i is assigned to be zero if unassigned.
        BigInteger[] vectorY = new BigInteger[dTilde];
        int coreRowIndex = 0;
        for (T data : coreDataSet) {
            int h1Value = dataH1Map.get(data);
            int h2Value = dataH2Map.get(data);
            int h3Value = dataH3Map.get(data);
            boolean[] rx = dataHrMap.get(data);
            BigInteger mp = BigInteger.ZERO;
            if (storage[h1Value] == null) {
                storage[h1Value] = BigInteger.ZERO;
            }
            if (storage[h2Value] == null) {
                storage[h2Value] = BigInteger.ZERO;
            }
            if (storage[h3Value] == null) {
                storage[h3Value] = BigInteger.ZERO;
            }
            // 3个哈希函数一定互不相同
            mp = zn.add(mp, storage[h1Value]);
            mp = zn.add(mp, storage[h2Value]);
            mp = zn.add(mp, storage[h3Value]);
            for (int rxIndex = 0; rxIndex < rx.length; rxIndex++) {
                if (rx[rxIndex]) {
                    if (storage[lm + rxIndex] == null) {
                        storage[lm + rxIndex] = BigInteger.ZERO;
                    }
                    mp = zn.add(mp, storage[lm + rxIndex]);
                }
            }
            BigInteger value = keyValueMap.get(data);
            vectorY[coreRowIndex] = zn.sub(value, mp);
            coreRowIndex++;
        }
        // Using Gaussian elimination solve the system
        // M˜* (P_{m' + C_1}, ..., P_{m' + C_{d˜})^T = (v'_{R_1}, ..., v'_{R_{d˜})^T.
        BigInteger[] vectorX = new BigInteger[setC.size()];
        SystemInfo systemInfo = znLinearSolver.solve(tildeStarMatrix, vectorY, vectorX, true);
        if (systemInfo.compareTo(SystemInfo.Inconsistent) == 0) {
            throw new ArithmeticException("无法完成编码过程，线性系统无解");
        }
        // 将求解结果更新到matrix里面
        int xVectorIndex = 0;
        for (int cIndex : setC) {
            storage[lm + cIndex] = vectorX[xVectorIndex];
            xVectorIndex++;
        }
        return storage;
    }

    /**
     * 给定待编码的键值对个数，计算左侧映射比特长度。
     *
     * @param n 待编码的键值对个数。
     * @return 左侧哈希比特长度，向上取整为Byte.SIZE的整数倍。
     */
    static int getLm(int n) {
        // 根据论文第5.4节，lm = 1.3 * n，向上取整到Byte.SIZE的整数倍
        return CommonUtils.getByteLength((int) Math.ceil(LEFT_EPSILON * n)) * Byte.SIZE;
    }

    /**
     * 给定待编码的键值对个数，计算右侧映射比特长度。
     *
     * @param n 待编码的键值对个数。
     * @return 右侧映射比特长度。向上取整为Byte.SIZE的整数倍。
     */
    static int getRm(int n) {
        // 根据论文第5.4节，r = 0.5 * log(n) + λ，向上取整到Byte.SIZE的整数倍
        // 但当n比较小时，哈希碰撞概率较高，会导致2-core图对应边数量很多
        // 测试结果为：2^8: 186，2^9: 328, 2^10: 561, 2^11: 907，当达到2^12时，骤降为4
        int r = CommonUtils.getByteLength(
                (int) Math.ceil(RIGHT_EPSILON * DoubleUtils.log2(n)) + CommonConstants.STATS_BIT_LENGTH
        ) * Byte.SIZE;
        if (n <= 1 << 8) {
            // 小于2^8，取0.5 * log(n) + λ和n的最大值
            return CommonUtils.getByteLength(Math.max(r, n)) * Byte.SIZE;
        } else if (n <= 1 << 9) {
            // 256 < n <= 512
            return CommonUtils.getByteLength(Math.min(n, 328)) * Byte.SIZE;
        } else if (n <= 1 << 10) {
            // 512 < n <= 1024
            return CommonUtils.getByteLength(Math.min(n, 561)) * Byte.SIZE;
        } else if (n <= 1 << 11) {
            // 1024 < n <= 2048
            return CommonUtils.getByteLength(907) * Byte.SIZE;
        } else {
            // n > 2048
            return r;
        }
    }

    /**
     * 生成3哈希-布谷鸟图。
     *
     * @param keyValueMap 键值对映射。
     * @return 3哈希-布谷鸟图。
     */
    H3CuckooTable<T> generateCuckooTable(Map<T, BigInteger> keyValueMap) {
        Set<T> keySet = keyValueMap.keySet();
        // 构造3哈希-布谷鸟图
        H3CuckooTable<T> h3CuckooTable = new H3CuckooTable<>(lm);
        for (T key : keySet) {
            int h1Value = dataH1Map.get(key);
            int h2Value = dataH2Map.get(key);
            int h3Value = dataH3Map.get(key);
            h3CuckooTable.addData(new Integer[]{h1Value, h2Value, h3Value}, key);
        }
        return h3CuckooTable;
    }

    @Override
    public int getNegLogFailureProbability() {
        // 根据论文第5.4节，r = 0.5 * log(n) + λ，失败概率为2^(-29.355)
        return 29;
    }
}

