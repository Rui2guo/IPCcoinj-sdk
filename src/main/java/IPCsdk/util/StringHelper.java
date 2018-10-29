package IPCsdk.util;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 字符串辅助类，提供一些字符串相关的辅助方法。
 * @author Yang Jingyu
 *
 */
public class StringHelper {
    
    /**
     * 输入字符串为null或者只包含空格时返回true。
     * 
     * @param str
     * @return
     */
    public static boolean isBlank(String str) {
        return str == null || str.trim().length() == 0;
    }
    
    /**
     * 输入字符串不是null，且包含非空格字符时返回true。
     * 
     * @param str
     * @return
     */
    public static boolean isNotBlank(String str) {
        return str != null && str.trim().length() != 0;
    }

    /**
     * 获取字符串的真实长度，中文长度算2。
     * @param str
     * @return
     */
    public static int getLength(String str){
        if(isBlank(str)){
            return 0;
        }
        
        Pattern p_str = Pattern.compile("[\\u4e00-\\u9fa5]+");
        
        int length = 0;
        for(int i = 0, len = str.length(); i < len; i ++){
            String temp = str.substring(i, i + 1);
            Matcher m = p_str.matcher(temp);
            if(m.find()){
                length += 2;
            } else {
                length ++;
            }
        }
        return length;
    }
    
    /**
     * 检验传入的字符串，如果为空或URL格式则返回True。
     * @param str
     * @return
     */
    public static boolean isBlankOrUrl(String str){
        // notifyUrl非空时必须是URL格式的字符串。
        boolean isUrlPass = true;
        if (isNotBlank(str)) {
            if(str.length() > 200){
                isUrlPass = false;
            } else {
                Pattern pattern = Pattern.compile("^((http|https)://)(([a-zA-Z0-9\\._-]+\\.[a-zA-Z]{2,6})|([0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}\\.[0-9]{1,3}))(:[0-9]{1,4})*(/[a-zA-Z0-9\\&%_\\./-~-]*)?$");
                Matcher matcher = pattern.matcher(str);
                isUrlPass = matcher.matches();
            }
        }
        return isUrlPass;
    }
}
