package IPCsdk.bip;

import java.security.Security;

import org.IPCcoinj.core.DumpedPrivateKey;
import org.IPCcoinj.params.MainNetParams;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.nem.core.crypto.KeyPair;
import org.nem.core.crypto.PrivateKey;
import org.nem.core.crypto.PublicKey;
import org.nem.core.model.Account;
import org.nem.core.model.NetworkInfos;

/**
 * @author yanchang.guo
 * @date 29/11/2017
 */

public class XemAddressGen {

    public static void main(String[] args) {
        if(args.length < 1){
            System.out.println("请输入私钥");
            return;
        }else{
            try {
                NetworkInfos.setDefault(NetworkInfos.getMainNetworkInfo());
                Security.addProvider(new BouncyCastleProvider());
                String privateKey = args[0];

                DumpedPrivateKey dumpedPrivateKey = DumpedPrivateKey.fromBase58(MainNetParams.get(), privateKey);
                PrivateKey prikey= new PrivateKey(dumpedPrivateKey.getKey().getPrivKey());
                KeyPair keyPair = new KeyPair(prikey);
                PublicKey publicKey = keyPair.getPublicKey();
                Account account = new Account(keyPair);
                System.out.println("private key : " + keyPair.getPrivateKey().toString());
                System.out.println("address     : " + account.toString());
            } catch (Throwable e) {
                System.out.println("输入的私钥有误");

            }
        }

    }

}
