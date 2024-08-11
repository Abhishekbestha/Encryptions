package com.hashing;

import java.security.MessageDigest;
import java.util.Arrays;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author 21701
 */
public class MD5 {

    public static void main(String[] args) throws Exception {
        System.out.println("Enter number 1(encrypt) or 2(decrypt): ");
        Scanner obj = new Scanner(System.in);
        int i = obj.nextInt();
        switch (i) {
            case 1:
                System.out.println("Enter text to encrypt: ");
                obj.nextLine();
                String text = obj.nextLine();
                String enc = encrypt(text);
                System.out.println("Encrypted Data:\t" + enc);
                break;
            case 2:
                System.out.println("Enter text to decrypt: ");
                obj.nextLine();
                String encText = obj.nextLine();
                String decrypt = decrypt(encText);
                System.out.println("Decrypted data:\t" + decrypt.trim());
                break;
        }
    }

    public static String encrypt(String plainText) {
        try {
            MessageDigest md = MessageDigest.getInstance("md5");
            byte[] digestOfPassword = md.digest("%#$%$^".getBytes("utf-8"));
            byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
            for (int j = 0, k = 16; j < 8;) {
                keyBytes[k++] = keyBytes[j++];
            }
            SecretKey key = new SecretKeySpec(keyBytes, "DESede");
            byte[] IV = {-16, 3, 45, 29, 0, 76, -83, 59};
            IvParameterSpec iv = new IvParameterSpec(IV);
            Cipher cipher = Cipher.getInstance("DESede/CBC/PKCS5Padding");
            cipher.init(1, key, iv);
            byte[] plainTextBytes = plainText.getBytes("utf-8");
            byte[] cipherText = cipher.doFinal(plainTextBytes);
            return new String(Base64.encode(cipherText));
        } catch (Exception ex) {
            return null;
        }
    }

    public static String decrypt(String ecryptedString) {
        try {
            byte[] message = Base64.decode(ecryptedString);
            final MessageDigest md = MessageDigest.getInstance("md5");
            final byte[] digestOfPassword = md.digest("%#$%$^".getBytes("utf-8"));
            final byte[] keyBytes = Arrays.copyOf(digestOfPassword, 24);
            for (int j = 0, k = 16; j < 8;) {
                keyBytes[k++] = keyBytes[j++];
            }
            final SecretKey key = new SecretKeySpec(keyBytes, "DESede");
            byte[] IV = {(byte) 240, (byte) 3, (byte) 45, (byte) 29, (byte) 0, (byte) 76, (byte) 173, (byte) 59};
            final IvParameterSpec iv = new IvParameterSpec(IV);
            final Cipher decipher = Cipher.getInstance("DESede/CBC/NoPadding");
            decipher.init(Cipher.DECRYPT_MODE, key, iv);
            final byte[] plainText = decipher.doFinal(message);

            return new String(plainText);
        } catch (Exception ex) {
            return ex.getLocalizedMessage();
        }
    }

}
