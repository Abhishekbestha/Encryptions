package com.hashing;

import java.security.Key;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import org.bouncycastle.util.encoders.Base64;

/**
 *
 * @author 21701
 */
public class AES {

    public static void main(String[] args) throws Exception {
        System.out.println("Enter number 1(encrypt) or 2(decrypt): ");
        Scanner obj = new Scanner(System.in);
        int i = obj.nextInt();
        switch (i) {
            case 1:
                System.out.println("Enter text to encrypt: ");
                obj.nextLine();
                String text = obj.nextLine();
                System.out.println("Enter key: ");
                String key = obj.nextLine();
                String enc = encrypt(text, key);
                System.out.println("Encrypted Data:\t" + enc);
                break;
            case 2:
                System.out.println("Enter text to decrypt: ");
                obj.nextLine();
                String encText = obj.nextLine();
                System.out.println("Enter key: ");
                String key1 = obj.nextLine();
                String decrypt = decrypt(encText, key1);
                System.out.println("Decrypted data:\t" + decrypt);
                break;
        }
    }

    public static String encrypt(String value, String Key) throws Exception {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKeySpec pbeKeySpec = new PBEKeySpec(Key.toCharArray(), new byte[]{0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76}, 1000, 384);
            Key secretKey = factory.generateSecret(pbeKeySpec);

            byte[] key1 = new byte[32];
            byte[] iv = new byte[16];

            System.arraycopy(secretKey.getEncoded(), 0, key1, 0, 32);
            System.arraycopy(secretKey.getEncoded(), 32, iv, 0, 16);

            IvParameterSpec iv1 = new IvParameterSpec(iv);
            SecretKeySpec skeySpec = new SecretKeySpec(key1, "AES");
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);

            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skeySpec, ivSpec);

            byte[] encrypted = cipher.doFinal(value.getBytes("UTF-8"));
            String encrypteddata = new String(Base64.encode(encrypted));
            return encrypteddata;
        } catch (Exception ex) {
            return null;
        }
    }

    public static String decrypt(String encrypted, String Key) throws Exception {
        try {
            SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
            PBEKeySpec pbeKeySpec = new PBEKeySpec(Key.toCharArray(), new byte[]{0x49, 0x76, 0x61, 0x6e, 0x20, 0x4d, 0x65, 0x64, 0x76, 0x65, 0x64, 0x65, 0x76}, 1000, 384);

            Key secretKey = factory.generateSecret(pbeKeySpec);
            byte[] key1 = new byte[32];
            byte[] iv = new byte[16];
            System.arraycopy(secretKey.getEncoded(), 0, key1, 0, 32);
            System.arraycopy(secretKey.getEncoded(), 32, iv, 0, 16);

            IvParameterSpec iv1 = new IvParameterSpec(iv);
            SecretKeySpec skeySpec = new SecretKeySpec(key1, "AES");
            AlgorithmParameterSpec ivSpec = new IvParameterSpec(iv);
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, skeySpec, ivSpec);
            byte[] data = Base64.decode(encrypted);
            byte[] original = cipher.doFinal(data);
            String base = new String(Base64.encode(original));
            String val = String.valueOf(original);
            String converted = new String(original);
            return converted;
        } catch (Exception ex) {
            return null;
        }
    }

}
