package IPCsdk.crypto;

import com.lambdaworks.crypto.SCrypt;
import org.IPCcoinj.core.Address;
import org.IPCcoinj.core.Base58;
import org.IPCcoinj.core.NetworkParameters;
import org.IPCcoinj.crypto.BIP38PrivateKey;
import org.spongycastle.util.Arrays;
import IPCsdk.core.KeyGenerator;
import IPCsdk.header.HeadInfo;
import IPCsdk.util.Tools;

/**
 * BIP38对应的实现： https://github.com/bitcoin/bips/blob/master/bip-0038.mediawiki
 * 
 * 一种使用密码加密私钥的规范。
 */
public class Bip38 {

    private static final String ALGORITHM = "AES/ECB/Pkcs7Padding";

    /**
     * 根据passphrase将私钥转为Bip38格式。
     * 
     * @param privateKey
     * @param passphrase
     * @return
     * @throws Exception
     */
    public static String encryptToBip38(String privateKey, String passphrase) throws Exception {
        byte[] priv_byte = Base58.decode(privateKey);

        HeadInfo head = HeadInfo.getInfoByByte(priv_byte[0]);
        KeyGenerator gene = KeyGenerator.fromPrivkeyWif(privateKey);
        Address address = gene.getAddress(head.getParam());

        priv_byte = Arrays.copyOfRange(priv_byte, 1, priv_byte.length - 4);

        // 1 addresshash = SHA256(SHA256(address))
        byte[] addresshash = DigestHash.sha256X2(address.toString().getBytes());
        byte[] salt = Arrays.copyOfRange(addresshash, 0, 4);

        // 2 Derive a key from the passphrase using scrypt
        int n = 16384, r = 8, p = 8, length = 64;
        byte[] key = SCrypt.scrypt(passphrase.getBytes(), salt, n, r, p, length);

        byte[] derivedhalf1 = Arrays.copyOfRange(key, 0, 32);
        byte[] derivedhalf2 = Arrays.copyOfRange(key, 32, 64);

        // 3
        byte[] block1 = Tools.xor(Arrays.copyOfRange(priv_byte, 0, 16), Arrays.copyOfRange(derivedhalf1, 0, 16));
        byte[] encryptedhalf1 = AES.encrypt(block1, derivedhalf2, null, ALGORITHM);

        byte[] block2 = Tools.xor(Arrays.copyOfRange(priv_byte, 16, 32), Arrays.copyOfRange(derivedhalf1, 16, 32));
        byte[] encryptedhalf2 = AES.encrypt(block2, derivedhalf2, null, ALGORITHM);

        byte iscompress = (byte) ((priv_byte.length == 33 && priv_byte[32] == 1) ? 0xe0 : 0xc0);

        byte[] result = new byte[39 + 4];
        result[0] = (byte) 0x01;
        result[1] = (byte) 0x42;
        result[2] = (byte) iscompress;

        System.arraycopy(salt, 0, result, 3, 4);
        System.arraycopy(encryptedhalf1, 0, result, 7, 16);
        System.arraycopy(encryptedhalf2, 0, result, 23, 16);

        // add checkSum
        byte[] checkSum = DigestHash.sha256(DigestHash.sha256(Arrays.copyOfRange(result, 0, 39)));
        System.arraycopy(checkSum, 0, result, 39, 4);

        return Base58.encode(result);
    }

    /**
     * 使用passphrase解码一个Bip38格式的私钥。
     * 
     * @param bip38String
     * @param passphrase
     * @param param
     * @return
     * @throws Exception
     */
    public static String decode(String bip38String, String passphrase, NetworkParameters param)
            throws Exception {
        BIP38PrivateKey bip38Key = BIP38PrivateKey.fromBase58(param, bip38String);
        return bip38Key.decrypt(passphrase).getPrivateKeyEncoded(param).toString();
    }
}
