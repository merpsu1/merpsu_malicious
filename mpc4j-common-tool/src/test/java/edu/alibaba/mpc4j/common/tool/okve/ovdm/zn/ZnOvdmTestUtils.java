package edu.alibaba.mpc4j.common.tool.okve.ovdm.zn;

import edu.alibaba.mpc4j.common.tool.CommonConstants;
import edu.alibaba.mpc4j.common.tool.galoisfield.zp.ZpManager;
import edu.alibaba.mpc4j.common.tool.utils.BigIntegerUtils;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.SecureRandom;
import java.util.HashMap;
import java.util.Map;
import java.util.stream.IntStream;

/**
 * Zn-OVDM测试工具类。
 *
 * @author Weiran Liu
 * @date 2022/4/19
 */
class ZnOvdmTestUtils {
    /**
     * 私有构造函数
     */
    private ZnOvdmTestUtils() {
        // empty
    }


//    static final BigInteger p = new BigInteger("191015776550387637622786539895443499727056" +
//            "2355879660246299093773776102180392163383348915349802393383996086005465366361264612" +
//            "490469565897131623411409988948107476342432872181978383790054968480573529305683626127" +
//            "93701893753730355545688491949188674057375180222199887216199238847325920414215941815853" +
//            "52942805684234496925559985113857914270908624094397546837390244642948919113338410597782029" +
//            "8243461517417878890633274970160230987555395483176044057797112674237593682237966172432286212" +
//            "9141636603791961700432258995704830353109792079741104097420232611950840658505087825938216058765" +
//            "6323930893294268693943280591061106681712347842389");
//
//    static final BigInteger q = new BigInteger("285781347615596787411285421726104839378637755261647709160518375" +
//            "609121765351366991731210848773303099108215186509313486106673557964130654863532361442018144823901537662" +
//            "20286942494116912408401865678679412278002108670157353361784271898572349431161515539400556197126732322" +
//            "16793136972821214255520722939864764885068130334219848892082658498281672099804530972665683584992557898" +
//            "74792610629884334443794410428554571608307898771911889610927213684771947703534380193691362721018917006" +
//            "970463328138394944525114433837563214252911516012994108540687159785719769808647209066222996875973118272" +
//            "03025891308021289996131055229584586164970153241");

    static final BigInteger p = ZpManager.getPrime(CommonConstants.BLOCK_BIT_LENGTH);

    static final BigInteger q = ZpManager.getPrime(CommonConstants.BLOCK_BIT_LENGTH);

    /**
     * 默认质数
     */
    static final BigInteger DEFAULT_MOD = p.multiply(p).multiply(q).multiply(q);
    /**
     * 随机状态
     */
    static final SecureRandom SECURE_RANDOM = new SecureRandom();

    static Map<ByteBuffer, BigInteger> randomKeyValueMap(int size) {
        Map<ByteBuffer, BigInteger> keyValueMap = new HashMap<>();
        IntStream.range(0, size).forEach(index -> {
            byte[] keyBytes = new byte[CommonConstants.BLOCK_BYTE_LENGTH];
            SECURE_RANDOM.nextBytes(keyBytes);
            BigInteger value = BigIntegerUtils.randomPositive(DEFAULT_MOD, SECURE_RANDOM);
            keyValueMap.put(ByteBuffer.wrap(keyBytes), value);
        });
        return keyValueMap;
    }
}

