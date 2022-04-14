package com.example.demo.security.util;

import org.springframework.stereotype.Component;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Base64;
import java.util.HexFormat;

@Component
public class SecurityCipherUtil {

    private static final String CIPHER = "AES";
    private static final String SECRET_KEY = "B8AE39D88056A94637E463D769852915";

    private static final SecretKeySpec secretKey;

    static {
        // Hex-encoded AES key generated with: openssl enc -aes-128-cbc -k secret -P -md sha1 -pbkdf2
        byte[] key = HexFormat.of().parseHex(SECRET_KEY);
        secretKey = new SecretKeySpec(key, CIPHER);
    }

    public static String encrypt(String strToEncrypt) {
        if (strToEncrypt == null) return null;

        try {
            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] encryptedStr = cipher.doFinal(strToEncrypt.getBytes(StandardCharsets.UTF_8));

            return Base64.getEncoder().encodeToString(encryptedStr);
        } catch (Exception e) {
            return null;
        }
    }


    public static String decrypt(String strToDecrypt) {
        if (strToDecrypt == null) return null;

        try {
            byte[] encryptedStr = Base64.getDecoder().decode(strToDecrypt);

            Cipher cipher = Cipher.getInstance(CIPHER);
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            byte[] decryptedStr = cipher.doFinal(encryptedStr);

            return new String(decryptedStr, StandardCharsets.UTF_8);
        } catch (Exception e) {
            return null;
        }
    }

}
