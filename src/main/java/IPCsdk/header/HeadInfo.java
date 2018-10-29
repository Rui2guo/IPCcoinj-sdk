package IPCsdk.header;

import org.IPCcoinj.core.NetworkParameters;
import org.IPCcoinj.params.MainNetParams;
import org.IPCcoinj.params.TestNet3Params;

import java.io.Serializable;

/**
 * 标识地址、私钥首字节信息。
 */
public class HeadInfo implements Serializable {

    private static final long serialVersionUID = -7020296768484580512L;

    /**
     * 根据地址或私钥的头字节，获取相关信息。
     * 
     * @param version
     * @return
     */
    public static HeadInfo getInfoByByte(byte version) {
        if (version == (byte) (0X0) || version == (byte) (0X80)) {
            return btcMain();
        }
        if (version == (byte) (0X6f) || version == (byte) (0X6f + 0X80)) {
            return btcTest();
        }
        return null;
    }

    private HeadInfo(String name, String network, byte addressPrefix, byte privatePrefix, NetworkParameters param) {
        this.name = name;
        this.network = network;
        this.addressPrefix = addressPrefix;
        this.privatePrefix = privatePrefix;
        this.param = param;
    }

    /**
     * 获取比特币正式网络相关的参数。
     * @return
     */
    public static HeadInfo btcMain() {
        NetworkParameters param = MainNetParams.get();
        HeadInfo head = new HeadInfo("Bitcoin", "Mainnet", (byte) (0X0), (byte) (0X80), param);
        return head;
    }

    /**
     * 获取比特币测试网络相关的参数。
     * @return
     */
    public static HeadInfo btcTest() {
        NetworkParameters param = TestNet3Params.get();
        HeadInfo head = new HeadInfo("Bitcoin", "Testnet", (byte) (0X6f), (byte) (0X6f + 0X80), param);
        return head;
    }
//
//    /**
//     * 获取莱特币正式网络相关的参数。
//     * @return
//     */
//    public static HeadInfo ltcMain() {
//        NetworkParameters param = LiteMainNetParam.get();
//        HeadInfo head = new HeadInfo("Litecoin", "Mainnet", (byte) (0X30), (byte) (0X30 + 0X80), param);
//        return head;
//    }

    // 网络名称。
    private String name;

    // 网络类型。
    private String network;

    // 地址首字节。
    private byte addressPrefix;

    // 私钥首字节。
    private byte privatePrefix;

    private NetworkParameters param;

    public String getName() {
        return name;
    }

    public String getNetwork() {
        return network;
    }

    public byte getAddressPrefix() {
        return addressPrefix;
    }

    public byte getPrivatePrefix() {
        return privatePrefix;
    }

    public NetworkParameters getParam() {
        return param;
    }
}
