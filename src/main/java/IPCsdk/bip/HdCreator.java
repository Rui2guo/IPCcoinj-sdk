package IPCsdk.bip;

import org.IPCcoinj.core.Base58;
import org.IPCcoinj.core.DumpedPrivateKey;
import org.IPCcoinj.core.ECKey;
import org.IPCcoinj.core.NetworkParameters;
import org.IPCcoinj.core.Utils;
import org.IPCcoinj.crypto.DeterministicKey;
import org.IPCcoinj.crypto.HDKeyDerivation;
import org.IPCcoinj.params.MainNetParams;

public class HdCreator {

    private static boolean onlyPub = false;

    public static void main(String[] args) {
        System.out.println("只输入一个参数：输入私钥");
        System.out.println();

        if (args.length == 1 && args[0] != null && args[0].trim().length() != 0) {
            NetworkParameters params = MainNetParams.get();
            ECKey ecKey = decodeEcKey(args[0].trim(), params);
            if (ecKey == null) {
                System.out.println("参数解析失败，WIF格式私钥字符串输入错误！");
                return;
            }
            System.out.println("输入的私钥： " + args[0].trim());
            System.out.println("私钥对应的公钥： " + ecKey.getPublicKeyAsHex());
//            System.out.println("私钥对应的地址： " + ecKey.toAddress(params));
            return;
        }

        if (args.length != 2 || args[0] == null || args[0].trim().length() == 0 || args[1] == null
                || args[1].trim().length() == 0) {
            System.out.println("参数个数不对或内容为空！");
            return;
        }

        NetworkParameters params = MainNetParams.get();
        ECKey ecKey = decodeEcKey(args[0].trim(), params);
        if (ecKey == null) {
            System.out.println("参数解析失败，第一个参数要求是：WIF格式私钥，或十六进制公钥！");
            return;
        }
        byte[] chainCode = decodeHex(args[1].trim());
        if (chainCode == null || chainCode.length != 32) {
            System.out.println("参数解析失败，第二个参数要求是：64位的十六进制字符串！");
            return;
        }

        System.out.println("输入的密钥： " + args[0].trim());
        System.out.println("输入的chainCode： " + args[1].trim());
        if (!onlyPub) {
            DeterministicKey deterKey = HDKeyDerivation
                    .createMasterPrivKeyFromBytes(ecKey.getPrivKeyBytes(), chainCode);
            System.out.println("私钥序列化： " + deterKey.serializePrivB58(params));
            System.out.println("公钥序列化： " + deterKey.serializePubB58(params));
        } else {
            DeterministicKey deterKey = HDKeyDerivation
                    .createMasterPubKeyFromBytes(Utils.HEX.decode(args[0].trim()), chainCode);
            System.out.println("私钥序列化： " + null);
            System.out.println("公钥序列化： " + deterKey.serializePubB58(params));
        }
    }

    /**
     * 将WIF格式的私钥或十六进制的公钥字符串转换为ECKey。
     * 
     * @param str
     * @return
     */
    private static ECKey decodeEcKey(String str, NetworkParameters params) {
        try {
            byte[] result = Utils.HEX.decode(str);
            onlyPub = true;
            return ECKey.fromPublicOnly(result);
        } catch (Exception e) {
        }
        try {
            Base58.decode(str);
            DumpedPrivateKey dpk = DumpedPrivateKey.fromBase58(params, str);
            return dpk.getKey();
        } catch (Exception e) {

        }
        return null;
    }

    /**
     * 将十六进制字符串解码为byte数组。
     * 
     * @param str
     * @return
     */
    private static byte[] decodeHex(String str) {
        try {
            return Utils.HEX.decode(str.toLowerCase());
        } catch (Exception e) {

        }
        return null;
    }

}
