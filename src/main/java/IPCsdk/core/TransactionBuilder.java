package IPCsdk.core;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.google.common.base.Objects;
import com.google.common.collect.ImmutableMap;
import org.IPCcoinj.core.Address;
import org.IPCcoinj.core.AddressFormatException;
import org.IPCcoinj.core.Coin;
import org.IPCcoinj.core.ECKey;
import org.IPCcoinj.core.ECKey.ECDSASignature;
import org.IPCcoinj.core.NetworkParameters;
import org.IPCcoinj.core.Sha256Hash;
import org.IPCcoinj.core.Transaction;
import org.IPCcoinj.core.Transaction.SigHash;
import org.IPCcoinj.core.Utils;
import org.IPCcoinj.crypto.TransactionSignature;
import org.IPCcoinj.script.Script;
import org.IPCcoinj.script.ScriptBuilder;

/**
 * 用于签名信息的构建。
 */
public class TransactionBuilder {

    private NetworkParameters params;

    private Transaction transaction;

    private List<InputInfo> inputList = new ArrayList<InputInfo>();

    private List<OutputInfo> outputList = new ArrayList<OutputInfo>();

    private Map<Integer, SignInfo> signInfoMap = new HashMap<Integer, SignInfo>();
    private Map<Integer, String> pubKeyMap = new HashMap<Integer, String>();

    private Map<Integer, List<ECDSASignature>> partSignMap =
            new HashMap<Integer, List<ECDSASignature>>();

    private List<String> msgList = new ArrayList<String>();

    private int type = 0;

    public TransactionBuilder(NetworkParameters params) {
        if (params == null) {
            throw new IllegalArgumentException("网络类型参数不能为空！");
        }
        this.params = params;
    }

    /**
     * 添加一个输入的信息。
     *
     * @param txId：    上一输出的txid。
     * @param txIndex： 上一输出对应的序号。
     */
    public void addInput(String txId, int txIndex) {
        InputInfo input = new InputInfo(txId, txIndex);
        if (inputList.contains(input)) {
            throw new IllegalArgumentException("输入中已包含该交易信息！");
        }
        inputList.add(input);
        reset();
    }

    /**
     * 添加留言信息，不能超过80字符（16进制字符串长度限制为160）。
     *
     * @param msg
     */
    public void addOpReturn(String msg) {
        if (msg == null || msg.trim().length() == 0) {
            throw new IllegalArgumentException("输入了空的留言信息！");
        }
        if (msg.length() > 160) {
            throw new IllegalArgumentException("留言信息不能超过80字符！");
        }
        try {
            Utils.HEX.decode(msg);
        } catch (Exception e) {
            throw new IllegalArgumentException("只支持16进制格式的字符串！");
        }

        if (msgList.contains(msg)) {
            throw new IllegalArgumentException("多次输入了相同的留言信息！");
        }
        msgList.add(msg);
        reset();
    }

    /**
     * 在添加新的输入、输出、签名信息时，清空原有的交易信息。
     */
    private void reset() {
        this.transaction = null;
        this.partSignMap.clear();
    }

    /**
     * 增加一个输出。
     *
     * @param address： 要付款到的比特币地址。
     * @param value：   要付到该地址的额度。
     */
    public void addOutput(String address, Coin value) {
        try {
            Address toAddress = Address.fromString(params, address);
            this.outputList.add(new OutputInfo(toAddress, value));

            reset();
        } catch (AddressFormatException e) {
            throw new IllegalArgumentException("错误的地址格式！");
        }
    }

    /**
     * 增加一个签名用的私钥信息。
     *
     * @param index：         添加输入时的顺序，从0开始。
     * @param privateKeyWif： 所添加的输入中，接收地址对应的私钥。
     * @param redeemScript：  多签形式的接收地址对应的脚本。
     */
    public void addSignInfo(int index, String privateKeyWif, String redeemScript) {
        if (index < 0 || privateKeyWif == null || privateKeyWif.trim().length() == 0) {
            throw new IllegalArgumentException("序号为负或私钥字段为空！");
        }

        signInfoMap.put(index, new SignInfo(privateKeyWif, redeemScript));
        reset();
    }

    public void addPubKey(int index, String privateKeyWif) {
        pubKeyMap.put(index, privateKeyWif);
    }

    /**
     * 根据输入、输出、签名等信息构建交易对象，并返回16进制编码的序列化信息。
     *
     * @return
     */
    public String build() {
        if (inputList.size() == 0) {
            throw new IllegalArgumentException("交易中至少需要有一个输入信息！");
        }
        if (outputList.size() == 0 && msgList.size() == 0) {
            throw new IllegalArgumentException("交易中至少需要有一个输出信息！");
        }
        if (signInfoMap.size() != inputList.size()) {
            throw new IllegalArgumentException("签名信息的数量和输入信息的数量不一致！");
        }

        // 初始化交易。
        transaction = new Transaction(params);


        // 记录添加输入时使用的脚本，方便在签名时使用。
        List<Script> scriptList = new ArrayList<Script>();
        // 记录从WIF格式私钥解析的ECKey对象，方便在签名时使用。
        List<ECKey> ecKeyList = new ArrayList<ECKey>();

        // 处理所有输入。
        int len = inputList.size();
        // 避免出现多次执行build导致输入被累加的情况。
        for (int i = 0; i < len; i++) {
            InputInfo input = inputList.get(i);


            //获取私钥和redeemScript:builder.addSignInfo(0, addrNode1.getEcKey().getPrivateKeyAsWiF(param), redeemScript)
            SignInfo signInfo = signInfoMap.get(i);

            //处理私钥
            Sha256Hash tx256Hash = Sha256Hash.wrap(input.getTxId());
            KeyGenerator key = KeyGenerator.fromPrivkeyWif(signInfo.getPrivateKey());
            ecKeyList.add(key.getEcKey());


            // 脚本为空时直接构建Script；非空时解析脚本获取Script。
            Script script = null;
//            if (!signInfo.isMultSig()) {
//                script = new Script(Utils.HEX.decode(signInfo.getRedeemScript()));
//            } else {
//                script = ScriptBuilder.createSingleScript(key.getAddress(params));
//            }

            script = ScriptBuilder.createSingleScript(key.getAddress(params));
            scriptList.add(script);

            transaction.addInput(tx256Hash, input.getIndex(), script);
        }

        // 添加输出信息。
        for (OutputInfo out : outputList) {
            transaction.addOutput(out.getValue(), out.getAddress(), type);
        }
        if (msgList.size() != 0) {
            for (String msg : msgList) {
                transaction.addOutput(Coin.valueOf(0),
                        ScriptBuilder.createOpReturnScript(Utils.HEX.decode(msg)), type);
            }
        }

        // 对输入逐个签名。  redeemScript
        for (int i = 0; i < len; i++) {
            Script script = scriptList.get(i);
            ECKey eckey = ecKeyList.get(i);

            Sha256Hash hashForSign = transaction.hashForSignature(i, script, SigHash.ALL, false);
            ECDSASignature signature = eckey.sign(hashForSign);
            TransactionSignature tranSign = new TransactionSignature(signature, SigHash.ALL, false);

            Script scriptSig = null;
            SignInfo signInfo = signInfoMap.get(i);
            // 如果是该输入是多签，则存储相应的签名中间信息。
//            if (!signInfo.isMultSig()) {
//                List<ECDSASignature> partSignList = partSignMap.get(i);
//                if (partSignList == null) {
//                    partSignList = new ArrayList<ECDSASignature>();
//                    partSignMap.put(i, partSignList);
//                }
//                partSignList.add(signature);
//
//                List<TransactionSignature> signatureList = new ArrayList<TransactionSignature>();
//                signatureList.add(tranSign);
//
//                Script multiSigScript = new Script(Utils.HEX.decode(signInfo.getRedeemScript()));
//                scriptSig =
//                        ScriptBuilder.createP2SHMultiSigInputScript(signatureList, multiSigScript);
//
//            } else {
//                scriptSig = ScriptBuilder.createInputScript(tranSign, eckey);
//
//            }

            scriptSig = ScriptBuilder.createInputScript(tranSign, eckey);
            transaction.getInput(i).setScriptSig(scriptSig);
        }

        return new String(Utils.HEX.encode(transaction.bitcoinSerialize()));
    }


    /**
     * 根据输入、输出、签名等信息构建交易对象，并返回16进制编码的序列化信息。
     *
     * @return
     */
    public String buildSingle() {
        if (inputList.size() == 0) {
            throw new IllegalArgumentException("交易中至少需要有一个输入信息！");
        }
        if (outputList.size() == 0 && msgList.size() == 0) {
            throw new IllegalArgumentException("交易中至少需要有一个输出信息！");
        }
        if (signInfoMap.size() != inputList.size()) {
            throw new IllegalArgumentException("签名信息的数量和输入信息的数量不一致！");
        }

        // 初始化交易。
        transaction = new Transaction(params);


        // 记录添加输入时使用的脚本，方便在签名时使用。
        List<Script> scriptList = new ArrayList<Script>();
        // 记录从WIF格式私钥解析的ECKey对象，方便在签名时使用。
        List<ECKey> ecKeyList = new ArrayList<ECKey>();

        // 处理所有输入。
        int len = inputList.size();
        // 避免出现多次执行build导致输入被累加的情况。
        for (int i = 0; i < len; i++) {
            InputInfo input = inputList.get(i);


            //获取私钥和redeemScript:builder.addSignInfo(0, addrNode1.getEcKey().getPrivateKeyAsWiF(param), redeemScript)
            SignInfo signInfo = signInfoMap.get(i);

            //处理私钥
            Sha256Hash tx256Hash = Sha256Hash.wrap(input.getTxId());
            KeyGenerator key = KeyGenerator.fromPrivkeyWif(signInfo.getPrivateKey());
            ecKeyList.add(key.getEcKey());


            // 脚本为空时直接构建Script；非空时解析脚本获取Script。
            Script script = null;

            script = ScriptBuilder.createSingleScript(key.getAddress(params));
            scriptList.add(script);

            transaction.addInput(tx256Hash, input.getIndex(), script);
        }

        // 添加输出信息。
        for (OutputInfo out : outputList) {
            transaction.addOutput(out.getValue(), out.getAddress(), type);
        }
        if (msgList.size() != 0) {
            for (String msg : msgList) {
                transaction.addOutput(Coin.valueOf(0),
                        ScriptBuilder.createOpReturnScript(Utils.HEX.decode(msg)), type);
            }
        }

        // 对输入逐个签名。  redeemScript
        for (int i = 0; i < len; i++) {
            Script script = scriptList.get(i);
            ECKey eckey = ecKeyList.get(i);
            Sha256Hash hashForSign = Sha256Hash.wrap(script.toString().getBytes());

            ECDSASignature signature = eckey.sign(hashForSign);
            TransactionSignature tranSign = new TransactionSignature(signature, SigHash.ALL, false);

            Script scriptSig = null;
            SignInfo signInfo = signInfoMap.get(i);
            // 如果是该输入是多签，则存储相应的签名中间信息。
            if (signInfo.isMultSig()) {
                List<ECDSASignature> partSignList = partSignMap.get(i);
                if (partSignList == null) {
                    partSignList = new ArrayList<ECDSASignature>();
                    partSignMap.put(i, partSignList);
                }
                partSignList.add(signature);

                List<TransactionSignature> signatureList = new ArrayList<TransactionSignature>();
                signatureList.add(tranSign);

                Script multiSigScript = new Script(Utils.HEX.decode(signInfo.getRedeemScript()));
                scriptSig =
                        ScriptBuilder.createP2SHMultiSigInputScript(signatureList, multiSigScript);
            } else {
                scriptSig = ScriptBuilder.createInputScript(tranSign, eckey);
            }

            transaction.getInput(i).setScriptSig(scriptSig);
        }

        return new String(Utils.HEX.encode(transaction.bitcoinSerialize()));
    }


    /**
     * 根据输入、输出、签名等信息构建交易对象，并返回16进制编码的序列化信息。
     *
     * @return
     */
    public String buildIncomplete() {
        if (inputList.size() == 0) {
            throw new IllegalArgumentException("交易中至少需要有一个输入信息！");
        }
        if (outputList.size() == 0 && msgList.size() == 0) {
            throw new IllegalArgumentException("交易中至少需要有一个输出信息！");
        }
        if (signInfoMap.size() != inputList.size()) {
            throw new IllegalArgumentException("签名信息的数量和输入信息的数量不一致！");
        }

        // 初始化交易。
        transaction = new Transaction(params);

        // 记录添加输入时使用的脚本，方便在签名时使用。
        List<Script> scriptList = new ArrayList<Script>();
        // 记录从WIF格式私钥解析的ECKey对象，方便在签名时使用。
        List<ECKey> ecKeyList = new ArrayList<ECKey>();

        // 处理所有输入。
        int len = inputList.size();
        // 避免出现多次执行build导致输入被累加的情况。
        for (int i = 0; i < len; i++) {
            InputInfo input = inputList.get(i);

            SignInfo signInfo = signInfoMap.get(i);

            Sha256Hash tx256Hash = Sha256Hash.wrap(input.getTxId());
            KeyGenerator key = KeyGenerator.fromPrivkeyWif(signInfo.getPrivateKey());
            ecKeyList.add(key.getEcKey());

            // 脚本为空时直接构建Script；非空时解析脚本获取Script。
            Script script = null;
            if (signInfo.isMultSig()) {
                script = new Script(Utils.HEX.decode(signInfo.getRedeemScript()));
            } else {
                script = ScriptBuilder.createOutputScript(key.getAddress(params));
            }
            scriptList.add(script);

            transaction.addInput(tx256Hash, input.getIndex(), script);
        }

        // 添加输出信息。
        for (OutputInfo out : outputList) {
            transaction.addOutput(out.getValue(), out.getAddress(), type);
        }
        if (msgList.size() != 0) {
            for (String msg : msgList) {
                transaction.addOutput(Coin.valueOf(0),
                        ScriptBuilder.createOpReturnScript(Utils.HEX.decode(msg)), type);
            }
        }

        // 对输入逐个签名。
        for (int i = 0; i < len; i++) {
            Script script = scriptList.get(i);
            ECKey eckey = ecKeyList.get(i);

            Sha256Hash hashForSign = transaction.hashForSignature(i, script, SigHash.ALL, false);
            ECDSASignature signature = eckey.sign(hashForSign);
            TransactionSignature tranSign = new TransactionSignature(signature, SigHash.ALL, false);

            Script scriptSig = null;
            SignInfo signInfo = signInfoMap.get(i);
            // 如果是该输入是多签，则存储相应的签名中间信息。
            if (signInfo.isMultSig()) {
                List<TransactionSignature> signatureList = new ArrayList<>();
                signatureList.add(tranSign);
                signatureList.add(null);

                Script multiSigScript = new Script(Utils.HEX.decode(signInfo.getRedeemScript()));

                List<byte[]> sigs = new ArrayList<>();
                for (TransactionSignature temp : signatureList) {
                    if (temp != null) {
                        sigs.add(temp.encodeToBitcoin());
                    } else {
                        sigs.add(new byte[]{});
                    }
                }
                scriptSig = ScriptBuilder.createMultiSigInputScriptBytes(sigs, multiSigScript.getProgram());
            } else {
                scriptSig = ScriptBuilder.createInputScript(tranSign, eckey);
            }

            transaction.getInput(i).setScriptSig(scriptSig);
        }

        return Utils.HEX.encode(transaction.bitcoinSerialize());
    }

    /**
     * 获取组织好的16进制编码的序列化信息。
     *
     * @return
     */
    public String getSerialized() {
        if (transaction == null) {
            return build();
        }
        return new String(Utils.HEX.encode(transaction.bitcoinSerialize()));
    }

    /**
     * 获取交易的TXID。
     *
     * @return
     */
    public String getHash() {
        if (transaction == null) {
            build();
        }
        return transaction.getHashAsString();
    }

    /**
     * 对发出地址是多签的进行后续签名。
     *
     * @param index：         添加输入时的顺序。
     * @param privateKeyWif： 所添加的输入中，接收地址对应的私钥。
     * @param redeemScript：  多签形式的接收地址对应的脚本。
     * @return
     */
    public String signForMultiSign(int index, String privateKeyWif, String redeemScript) {
        if (index < 0 || privateKeyWif == null || privateKeyWif.trim().length() == 0
                || redeemScript == null || redeemScript.trim().length() == 0) {
            throw new IllegalArgumentException("序号为负或参数中的字段为空！");
        }

        SignInfo temp = signInfoMap.get(index);
        if (temp == null || !redeemScript.equals(temp.getRedeemScript())) {
            throw new IllegalArgumentException("脚本字符串和之前的输入不符！");
        }

        if (transaction == null) {
            build();
        }

        List<TransactionSignature> signatureList = new ArrayList<TransactionSignature>();
        List<ECDSASignature> partSignList = partSignMap.get(index);
        for (int i = 0, len = partSignList.size(); i < len; i++) {
            ECDSASignature signature = partSignList.get(i);
            TransactionSignature tranSign = new TransactionSignature(signature, SigHash.ALL, false);
            signatureList.add(tranSign);
        }

        Script multiSigScript = new Script(Utils.HEX.decode(redeemScript));
        Sha256Hash hash256 =
                transaction.hashForSignature(index, multiSigScript, SigHash.ALL, false);
        KeyGenerator privateKey = KeyGenerator.fromPrivkeyWif(privateKeyWif);

        ECDSASignature currSignature = privateKey.getEcKey().sign(hash256);
        TransactionSignature tranSignature =
                new TransactionSignature(currSignature, SigHash.ALL, false);
        signatureList.add(tranSignature);

        Script inputScript =
                ScriptBuilder.createP2SHMultiSigInputScript(signatureList, multiSigScript);
        transaction.getInput(index).setScriptSig(inputScript);

        // 更新中间信息的记录，加入当前签名信息。
        partSignList.add(currSignature);
        return new String(Utils.HEX.encode(transaction.bitcoinSerialize()));
    }

    /**
     * 按照输入的顺序获取各自签名后的中间结果。可用于多签中的后续签名。
     * <p>
     * 如果尚未构建，则先进行构建处理。
     *
     * @return 返回的是一个镜像。
     */
    public Map<Integer, List<ECDSASignature>> getPartSignMap() {
        if (transaction == null) {
            build();
        }
        return ImmutableMap.copyOf(partSignMap);
    }

    /**
     * 以字符串形式获取第一次签名的中间结果。
     * <p>
     * 如果尚未构建，则先进行构建处理。
     *
     * @return {输入顺序:签名结果}
     */
    public Map<String, String> getPartSignStrMap() {
        if (transaction == null) {
            build();
        }

        int size = partSignMap.size();
        Map<String, String> result = new HashMap<String, String>(size * 2);
        for (int i = 0; i < size; i++) {
            List<ECDSASignature> signList = partSignMap.get(i);
            // 只取第一次签名后的，因此只读取列表中的第一个值。
            if (signList != null && signList.size() != 0) {
                ECDSASignature signature = signList.get(0);
                result.put(Integer.toString(i), Utils.HEX.encode(signature.encodeToDER()));
            }
        }
        return result;
    }

    /**
     * 输入相关的信息。
     */
    private class InputInfo {

        private String txId;

        private int index;

        public InputInfo(String txId, int index) {
            this.txId = txId;
            this.index = index;
        }

        public String getTxId() {
            return txId;
        }

        public int getIndex() {
            return index;
        }

        public int hashCode() {
            return Objects.hashCode(txId, index);
        }

        public boolean equals(Object obj) {
            if (obj == null || !(obj instanceof InputInfo)) {
                return false;
            }

            InputInfo other = (InputInfo) obj;
            return txId.equals(other.getTxId()) && index == other.getIndex();
        }
    }

    /**
     * 输出相关的信息。
     */
    private class OutputInfo {

        private Address address;

        private Coin value;

        public OutputInfo(Address address, Coin value) {
            this.address = address;
            this.value = value;
        }

        public Address getAddress() {
            return address;
        }

        public Coin getValue() {
            return value;
        }

        public int hashCode() {
            return Objects.hashCode(address, value);
        }

        public boolean equals(Object obj) {
            if (obj == null || !(obj instanceof OutputInfo)) {
                return false;
            }

            OutputInfo other = (OutputInfo) obj;
            return address.equals(other.getAddress()) && value.equals(other.getValue());
        }
    }

    /**
     * 用于存放TransactionBuilder中sign方法的参数。
     */
    private class SignInfo {

        // 所添加的输入中，接收地址对应的私钥。
        private String privateKey;

        // 多签形式的接收地址对应的脚本。
        private String redeemScript;

        public SignInfo(String privateKey, String redeemScript) {
            this.privateKey = privateKey;
            this.redeemScript = redeemScript;
        }

        public String getPrivateKey() {
            return privateKey;
        }

        public String getRedeemScript() {
            return redeemScript;
        }

        /**
         * 返回是否含有多签脚本。
         */
        public boolean isMultSig() {
            return redeemScript != null && redeemScript.trim().length() != 0;
        }
    }
}
