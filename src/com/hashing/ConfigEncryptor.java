package com.hashing;

/**
 *
 * @author 21701
 */
import Utilities.Base64Encoder;
import java.io.ByteArrayOutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;

public class ConfigEncryptor {

    private static final String ENCRYPT_ALGO = "AES/GCM/NoPadding";

    private static final int TAG_LENGTH_BIT = 128;

    private static final int IV_LENGTH_BYTE = 12;

    private static final int SALT_LENGTH_BYTE = 16;

    private static final Charset UTF_8 = StandardCharsets.UTF_8;

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
                String enc = encrypt(text, key.toCharArray());
                System.out.println("Encrypted Data:\t" + enc);
                break;
            case 2:
                System.out.println("Enter text to decrypt: ");
                obj.nextLine();
                String encText = obj.nextLine();
                System.out.println("Enter key: ");
                String key1 = obj.nextLine();
                String decrypt = decrypt(encText, key1.toCharArray());
                System.out.println("Decrypted data:\t" + decrypt);
                break;
        }
    }

    private static String encrypt(String plainText, char[] password) throws Exception {
        byte[] salt = getRandomNonce(16);
        byte[] iv = getRandomNonce(12);
        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(1, aesKeyFromPassword, new GCMParameterSpec(128, iv));
        byte[] cipherText = cipher.doFinal(plainText.getBytes(UTF_8));
        byte[] cipherTextWithIvSalt = ByteBuffer.allocate(iv.length + salt.length + cipherText.length).put(iv).put(salt).put(cipherText).array();
        return toBase64String(cipherTextWithIvSalt);
    }

    private static byte[] getRandomNonce(int numBytes) {
        byte[] nonce = new byte[numBytes];
        (new SecureRandom()).nextBytes(nonce);
        return nonce;
    }

    private static SecretKey getAESKeyFromPassword(char[] password, byte[] salt) throws NoSuchAlgorithmException, InvalidKeySpecException {
        SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA512");
        KeySpec spec = new PBEKeySpec(password, salt, 65536, 256);
        SecretKey secret = new SecretKeySpec(factory.generateSecret(spec).getEncoded(), "AES");
        return secret;
    }

    private static String toBase64String(byte[] data) throws Exception {
        Base64Encoder encoder = new Base64Encoder();
        int len = (data.length + 2) / 3 * 4;
        ByteArrayOutputStream bOut = new ByteArrayOutputStream(len);
        try {
            encoder.encode(data, 0, data.length, bOut);
        } catch (Exception e) {
            throw new Exception("exception encoding base64 string: " + e.getMessage(), e);
        }
        return fromByteArray(bOut.toByteArray());
    }

    private static String fromByteArray(byte[] bytes) {
        char[] chars = new char[bytes.length];
        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xFF);
        }
        return new String(chars);
    }

    private static String decrypt(String cipherText, char[] password) throws Exception {
        byte[] cipherTextWithIvSalt = java.util.Base64.getDecoder().decode(cipherText);
        ByteBuffer buffer = ByteBuffer.wrap(cipherTextWithIvSalt);

        byte[] iv = new byte[12];
        buffer.get(iv);

        byte[] salt = new byte[16];
        buffer.get(salt);

        byte[] encrypted = new byte[buffer.remaining()];
        buffer.get(encrypted);

        SecretKey aesKeyFromPassword = getAESKeyFromPassword(password, salt);
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");
        cipher.init(Cipher.DECRYPT_MODE, aesKeyFromPassword, new GCMParameterSpec(128, iv));
        byte[] decryptedBytes = cipher.doFinal(encrypted);

        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

}
