package hu.mse.common;

import java.security.MessageDigest;
import java.util.Arrays;

import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.apache.commons.codec.binary.Base64;

public class Encrypt {

    private static final String KEY = "HG58YZ3CR9+DSF/(=)_ss3";
    private static final int BYTE_SIZE = 8;

    public static String encrypt(String message) {
        String encodedCipherText = null;
        try {
            final MessageDigest md = MessageDigest.getInstance("md5");
            final byte[] digestOfPassword = md.digest(KEY.getBytes("utf-8"));
            final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
            for (int j = 0, k = 16; j < BYTE_SIZE; ) {
                keyBytes[k++] = keyBytes[j++];
            }
            final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
            final IvParameterSpec iv = new IvParameterSpec(new byte[BYTE_SIZE]);
            final Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, key, iv);

            final byte[] plainTextBytes = message.getBytes("utf-8");
            final byte[] cipherText = cipher.doFinal(plainTextBytes);
            encodedCipherText = Base64.encodeBase64String(cipherText);

        } catch (Exception e) {
            e.printStackTrace();
        }
        return encodedCipherText;
    }
}
