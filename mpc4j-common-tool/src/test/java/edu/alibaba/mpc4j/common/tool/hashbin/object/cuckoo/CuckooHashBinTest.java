package edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo;

import com.google.common.base.Preconditions;
import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.EnvType;
import edu.alibaba.mpc4j.common.tool.crypto.prf.Prf;
import edu.alibaba.mpc4j.common.tool.crypto.prf.PrfFactory;
import edu.alibaba.mpc4j.common.tool.hashbin.HashBinTestUtils;
import edu.alibaba.mpc4j.common.tool.hashbin.object.HashBinEntry;
import edu.alibaba.mpc4j.common.tool.hashbin.object.cuckoo.CuckooHashBinFactory.CuckooHashBinType;
import edu.alibaba.mpc4j.common.tool.utils.CommonUtils;
import edu.alibaba.mpc4j.common.tool.utils.ObjectUtils;
import org.apache.commons.lang3.StringUtils;
import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import java.nio.ByteBuffer;
import java.util.*;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

/**
 * 布谷鸟哈希测试。
 *
 * @author Weiran Liu
 * @date 2022/01/07
 */
@RunWith(Parameterized.class)
public class CuckooHashBinTest {
    /**
     * 随机测试轮数
     */
    private static final int MAX_RANDOM_ROUND = 50;
    /**
     * 默认元素数量
     */
    private static final int DEFAULT_N = CommonConstants.STATS_BIT_LENGTH;

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> configurations() {
        Collection<Object[]> configurations = new ArrayList<>();
        // NO_STASH_PSZ18_5_HASH
        configurations.add(new Object[] {
            CuckooHashBinType.NO_STASH_PSZ18_5_HASH.name(), CuckooHashBinType.NO_STASH_PSZ18_5_HASH
        });
        // NO_STASH_PSZ18_4_HASH
        configurations.add(new Object[] {
            CuckooHashBinType.NO_STASH_PSZ18_4_HASH.name(), CuckooHashBinType.NO_STASH_PSZ18_4_HASH
        });
        // NO_STASH_PSZ18_3_HASH
        configurations.add(new Object[] {
            CuckooHashBinType.NO_STASH_PSZ18_3_HASH.name(), CuckooHashBinType.NO_STASH_PSZ18_3_HASH
        });
        // NO_STASH_DRRT18
        configurations.add(new Object[] {
            CuckooHashBinType.NO_STASH_DRRT18.name(), CuckooHashBinType.NO_STASH_DRRT18
        });
        // NO_STASH_NAIVE
        configurations.add(new Object[] {
            CuckooHashBinType.NO_STASH_NAIVE.name(), CuckooHashBinType.NO_STASH_NAIVE
        });
        // NAIVE_2_HASH
        configurations.add(new Object[] {CuckooHashBinType.NAIVE_2_HASH.name(), CuckooHashBinType.NAIVE_2_HASH});
        // NAIVE_3_HASH
        configurations.add(new Object[] {CuckooHashBinType.NAIVE_3_HASH.name(), CuckooHashBinType.NAIVE_3_HASH});
        // NAIVE_4_HASH
        configurations.add(new Object[] {CuckooHashBinType.NAIVE_4_HASH.name(), CuckooHashBinType.NAIVE_4_HASH});
        // NAIVE_5_HASH
        configurations.add(new Object[] {CuckooHashBinType.NAIVE_5_HASH.name(), CuckooHashBinType.NAIVE_5_HASH});

        return configurations;
    }

    /**
     * 布谷鸟哈希通类型
     */
    private final CuckooHashBinType type;

    public CuckooHashBinTest(String name, CuckooHashBinType type) {
        Preconditions.checkArgument(StringUtils.isNotBlank(name));
        this.type = type;
    }

    @Test
    public void testIllegalInputs() {
        // 密钥长度不正确
        try {
            byte[][] lessKeys = CommonUtils.generateRandomKeys(
                CuckooHashBinFactory.getHashNum(type) - 1, HashBinTestUtils.SECURE_RANDOM
            );
            CuckooHashBinFactory.createCuckooHashBin(EnvType.STANDARD, type, DEFAULT_N, lessKeys);
            throw new IllegalStateException("ERROR: successfully create CuckooHashBin with less keys");
        } catch (AssertionError ignored) {

        }
        try {
            byte[][] moreKeys = CommonUtils.generateRandomKeys(
                CuckooHashBinFactory.getHashNum(type) + 1, HashBinTestUtils.SECURE_RANDOM
            );
            CuckooHashBinFactory.createCuckooHashBin(EnvType.STANDARD, type, DEFAULT_N, moreKeys);
            throw new IllegalStateException("ERROR: successfully create CuckooHashBin with more keys");
        } catch (AssertionError ignored) {

        }
        // 尝试创建插入0个元素的哈希桶
        try {
            byte[][] initKeys = CommonUtils.generateRandomKeys(
                CuckooHashBinFactory.getHashNum(type), HashBinTestUtils.SECURE_RANDOM
            );
            CuckooHashBinFactory.createCuckooHashBin(EnvType.STANDARD, type, 0, initKeys);
            throw new IllegalStateException("ERROR: successfully create CuckooHashBin with 0 maxSize");
        } catch (AssertionError ignored) {

        }
        byte[][] keys = CommonUtils.generateRandomKeys(
            CuckooHashBinFactory.getHashNum(type), HashBinTestUtils.SECURE_RANDOM
        );
        CuckooHashBin<ByteBuffer> hashBin = CuckooHashBinFactory.createCuckooHashBin(
            EnvType.STANDARD, type, DEFAULT_N, keys
        );
        // 尝试在未插入元素的时候插入虚拟元素
        try {
            hashBin.insertPaddingItems(HashBinTestUtils.SECURE_RANDOM);
            throw new IllegalStateException("ERROR: successfully insert padding items before inserting items");
        } catch (AssertionError ignored) {

        }
        try {
            hashBin.insertPaddingItems(ByteBuffer.wrap(new byte[0]));
            throw new IllegalStateException("ERROR: successfully insert empty items before inserting items");
        } catch (AssertionError ignored) {

        }
        // 尝试插入较多数量的元素
        try {
            List<ByteBuffer> items = HashBinTestUtils.randomByteBufferItems(DEFAULT_N + 1);
            hashBin.insertItems(items);
            throw new IllegalStateException("ERROR: successfully insert more items into CuckooHashBin");
        } catch (AssertionError ignored) {

        }
        // 尝试插入重复元素
        List<ByteBuffer> duplicateItems = HashBinTestUtils.randomByteBufferItems(DEFAULT_N - 2);
        duplicateItems.add(ByteBuffer.wrap(new byte[CommonConstants.BLOCK_BYTE_LENGTH]));
        duplicateItems.add(ByteBuffer.wrap(new byte[CommonConstants.BLOCK_BYTE_LENGTH]));
        boolean duplicateSuccess = false;
        while (!duplicateSuccess) {
            try {
                hashBin.insertItems(duplicateItems);
                //noinspection UnusedAssignment
                duplicateSuccess = true;
                throw new IllegalStateException("ERROR: successfully insert duplicated items into CuckooHashBin");
            } catch (ArithmeticException e) {
                keys = CommonUtils.generateRandomKeys(
                    CuckooHashBinFactory.getHashNum(type), HashBinTestUtils.SECURE_RANDOM
                );
                hashBin = CuckooHashBinFactory.createCuckooHashBin(EnvType.STANDARD, type, DEFAULT_N, keys);
            } catch (IllegalArgumentException ignored) {
                break;
            }
        }
        // 插入元素
        List<ByteBuffer> items = HashBinTestUtils.randomByteBufferItems(DEFAULT_N);
        boolean success = false;
        while (!success) {
            try {
                hashBin.insertItems(items);
                success = true;
            } catch (ArithmeticException ignored) {
                keys = CommonUtils.generateRandomKeys(
                    CuckooHashBinFactory.getHashNum(type), HashBinTestUtils.SECURE_RANDOM
                );
                hashBin = CuckooHashBinFactory.createCuckooHashBin(
                    EnvType.STANDARD, type, DEFAULT_N, keys
                );
            }
        }
        // 尝试再次插入元素
        try {
            List<ByteBuffer> moreItems = HashBinTestUtils.randomByteBufferItems(DEFAULT_N);
            hashBin.insertItems(moreItems);
            throw new IllegalStateException("ERROR: successfully insert items twice into CuckooHashBin");
        } catch (AssertionError ignored) {

        }
        // 尝试填充已存在的元素
        try {
            hashBin.insertPaddingItems(items.get(0));
            throw new IllegalStateException("ERROR: successfully treat existing item as the empty item");
        } catch (AssertionError ignored) {

        }
        hashBin.insertPaddingItems(HashBinTestUtils.SECURE_RANDOM);
        // 尝试再次填充虚拟元素
        try {
            hashBin.insertPaddingItems(HashBinTestUtils.SECURE_RANDOM);
            throw new IllegalStateException("ERROR: successfully insert padding items twice");
        } catch (AssertionError ignored) {

        }
    }

    @Test
    public void testType() {
        byte[][] keys = CommonUtils.generateRandomKeys(
            CuckooHashBinFactory.getHashNum(type), HashBinTestUtils.SECURE_RANDOM
        );
        CuckooHashBin<ByteBuffer> hashBin = CuckooHashBinFactory.createCuckooHashBin(
            EnvType.STANDARD, type, DEFAULT_N, keys
        );
        Assert.assertEquals(type, hashBin.getType());
    }

    @Test
    public void test1n() {
        testCuckooHashBin(1);
    }

    @Test
    public void test2n() {
        testCuckooHashBin(2);
    }

    @Test
    public void test3n() {testCuckooHashBin(3);}

    @Test
    public void test40n() {
        testCuckooHashBin(40);
    }

    @Test
    public void test256n() {
        testCuckooHashBin(256);
    }

    @Test
    public void test4096n() {
        testCuckooHashBin(4096);
    }

    private void testCuckooHashBin(int n) {
        for (int i = 0; i < MAX_RANDOM_ROUND; i++) {
            byte[][] keys = CommonUtils.generateRandomKeys(
                CuckooHashBinFactory.getHashNum(type), HashBinTestUtils.SECURE_RANDOM
            );
            CuckooHashBin<ByteBuffer> hashBin = CuckooHashBinFactory.createCuckooHashBin(
                EnvType.STANDARD, type, n, keys
            );
            assertEmptyHashBin(hashBin);
            // 插入元素
            List<ByteBuffer> items = HashBinTestUtils.randomByteBufferItems(n);
            boolean success = false;
            while (!success) {
                try {
                    hashBin.insertItems(items);
                    success = true;
                } catch (ArithmeticException ignored) {
                    keys = CommonUtils.generateRandomKeys(
                        CuckooHashBinFactory.getHashNum(type), HashBinTestUtils.SECURE_RANDOM
                    );
                    hashBin = CuckooHashBinFactory.createCuckooHashBin(EnvType.STANDARD, type, n, keys);
                }
            }
            assertInsertedCuckooHashBin(hashBin, items);
            assertHashBinPosition(hashBin, items, keys);
            // 插入虚拟元素
            hashBin.insertPaddingItems(HashBinTestUtils.SECURE_RANDOM);
            assertPaddingHashBin(hashBin, items);
            assertHashBinPosition(hashBin, items, keys);
            hashBin.clear();
            assertEmptyHashBin(hashBin);
            // 再次插入元素
            hashBin.insertItems(items);
            assertInsertedCuckooHashBin(hashBin, items);
            assertHashBinPosition(hashBin, items, keys);
            // 插入空元素
            hashBin.insertPaddingItems(ByteBuffer.wrap(new byte[CommonConstants.BLOCK_BYTE_LENGTH]));
            assertPaddingHashBin(hashBin, items);
            assertHashBinPosition(hashBin, items, keys);
            hashBin.clear();
            // 插入较小数量的元素
            items.remove(0);
            hashBin.insertItems(items);
            assertInsertedCuckooHashBin(hashBin, items);
            assertHashBinPosition(hashBin, items, keys);
            hashBin.clear();
            // 插入0个元素
            List<ByteBuffer> emptyItems = new LinkedList<>();
            hashBin.insertItems(emptyItems);
            assertInsertedCuckooHashBin(hashBin, emptyItems);
            assertHashBinPosition(hashBin, emptyItems, keys);
            hashBin.clear();
        }
    }

    private void assertEmptyHashBin(CuckooHashBin<ByteBuffer> cuckooHashBin) {
        // 验证状态
        Assert.assertFalse(cuckooHashBin.insertedItems());
        Assert.assertFalse(cuckooHashBin.insertedPaddingItems());
        // 验证数量
        Assert.assertEquals(0, cuckooHashBin.size());
        Assert.assertEquals(0, cuckooHashBin.itemSize());
        Assert.assertEquals(0, cuckooHashBin.itemNumInBins());
        Assert.assertEquals(0, cuckooHashBin.itemNumInStash());
        Assert.assertEquals(0, cuckooHashBin.paddingItemSize());
    }

    private void assertInsertedCuckooHashBin(CuckooHashBin<ByteBuffer> cuckooHashBin, List<ByteBuffer> items) {
        // 验证状态
        Assert.assertTrue(cuckooHashBin.insertedItems());
        Assert.assertFalse(cuckooHashBin.insertedPaddingItems());
        // 验证插入元素数量
        Assert.assertEquals(items.size(), cuckooHashBin.itemSize());
        Assert.assertEquals(0, cuckooHashBin.paddingItemSize());
        Assert.assertEquals(items.size(), cuckooHashBin.size());
        Assert.assertEquals(items.size(), cuckooHashBin.itemNumInBins() + cuckooHashBin.itemNumInStash());
        Assert.assertTrue(cuckooHashBin.itemNumInStash() <= cuckooHashBin.stashSize());
        // 并发验证所有的元素都在布谷鸟哈希桶中
        items.stream().parallel().forEach(item -> Assert.assertTrue(cuckooHashBin.contains(item)));
    }

    private void assertPaddingHashBin(CuckooHashBin<ByteBuffer> cuckooHashBin, List<ByteBuffer> items) {
        // 验证状态
        Assert.assertTrue(cuckooHashBin.insertedItems());
        Assert.assertTrue(cuckooHashBin.insertedPaddingItems());
        // 验证元素数量
        Assert.assertEquals(items.size(), cuckooHashBin.itemSize());
        Assert.assertEquals(cuckooHashBin.binNum() + cuckooHashBin.stashSize(), cuckooHashBin.size());
        Assert.assertEquals(
            cuckooHashBin.binNum() + cuckooHashBin.stashSize() - items.size(), cuckooHashBin.paddingItemSize()
        );
        // 并发验证所有的元素都在布谷鸟哈希桶中
        items.stream().parallel().forEach(item -> Assert.assertTrue(cuckooHashBin.contains(item)));
    }

    private void assertHashBinPosition(CuckooHashBin<ByteBuffer> cuckooHashBin, List<ByteBuffer> items, byte[][] keys) {
        // 外部初始化哈希函数，计算位置，验证外部计算的结果与内部计算结果相同
        Prf[] hashes = Arrays.stream(keys).map(key -> {
                Prf prf = PrfFactory.createInstance(EnvType.STANDARD, Integer.BYTES);
                prf.setKey(key);
                return prf;
            })
            .toArray(Prf[]::new);
        items.forEach(item -> {
            int[] positions = IntStream.range(0, keys.length)
                .map(index -> hashes[index].getInteger(ObjectUtils.objectToByteArray(item), cuckooHashBin.binNum()))
                .toArray();
            Set<ByteBuffer> positionItems = Arrays.stream(positions)
                .mapToObj(cuckooHashBin::getHashBinEntry)
                .filter(Objects::nonNull)
                .map(HashBinEntry::getItem)
                .collect(Collectors.toSet());
            positionItems.addAll(
                cuckooHashBin.getStash().stream().map(HashBinEntry::getItem).collect(Collectors.toList())
            );
            Assert.assertTrue(positionItems.contains(item));
        });
    }
}
