package com.digitalsignverify;

//package com.test;
//
////import static Classes.Utilities.errorStackTrace;
//import java.io.ByteArrayInputStream;
//import java.io.FileInputStream;
//import java.io.IOException;
//import java.nio.charset.Charset;
//import java.security.GeneralSecurityException;
//import java.security.InvalidKeyException;
//import java.security.KeyStore;
//import java.security.KeyStoreException;
//import java.security.MessageDigest;
//import java.security.NoSuchAlgorithmException;
//import java.security.PrivateKey;
//import java.security.Provider;
//import java.security.PublicKey;
//import java.security.SecureRandom;
//import java.security.Security;
//import java.security.UnrecoverableKeyException;
//import java.security.cert.CertificateException;
//import java.security.cert.X509Certificate;
//import java.security.spec.MGF1ParameterSpec;
//import java.util.Base64;
//import javax.crypto.Cipher;
//import javax.crypto.spec.OAEPParameterSpec;
//import javax.crypto.spec.PSource;
//import org.bouncycastle.crypto.BufferedBlockCipher;
//import org.bouncycastle.crypto.InvalidCipherTextException;
//import org.bouncycastle.crypto.engines.AESEngine;
//import org.bouncycastle.crypto.modes.CFBBlockCipher;
//import org.bouncycastle.crypto.params.KeyParameter;
//import org.bouncycastle.crypto.params.ParametersWithIV;
//import org.bouncycastle.jce.provider.BouncyCastleProvider;
//import sun.security.rsa.RSAPadding;
//
//public class HSMDecryptEncrypt {
//
//    private static Provider p11Provider;
//    private static Provider bcProvider = new BouncyCastleProvider();
//    private static final int PUBLIC_KEY_SIZE = 294;
//    private static final int EID_SIZE = 32;
//    private static final int SECRET_KEY_SIZE = 256;
//    private static final String DIGEST_ALGORITHM = "SHA-256";
//    private static final int VECTOR_SIZE = 16;
//    private static final int HMAC_SIZE = 32;
//    private static final int BLOCK_SIZE = 128;
//    private static final byte[] HEADER_DATA = "VERSION_1.0".getBytes(Charset.forName("UTF-8"));
//    private static KeyStore keyStore = null;
//    private static char[] keyStorePassword = "emudhra".toCharArray();
//
//    public HSMDecryptEncrypt(String library, char[] pin) throws Exception {
//        keyStorePassword = pin;
//        String configuration = "name=HSM\n" + "library=" + library + "\n";
//        p11Provider = new sun.security.pkcs11.SunPKCS11(new ByteArrayInputStream(configuration.getBytes(Charset.forName("UTF-8"))));
//        Security.addProvider(p11Provider);
//        keyStore = KeyStore.getInstance("PKCS11");
//        keyStore.load(null, pin);
//    }
//
//    private static KeyStore.PrivateKeyEntry getKeyFromKeyStore(String alias) throws Exception {
//
//        try {
//            String pfxFilePath = "D:\\env\\eSign\\Test-Class3DocumentSigner2014.pfx";
//            keyStore = KeyStore.getInstance("PKCS12");
//            FileInputStream fis = new FileInputStream(pfxFilePath);
//            keyStore.load(fis, "emudhra".toCharArray());
//            fis.close();
//            return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, new KeyStore.PasswordProtection(keyStorePassword));
//
//        } catch (Exception e) {
//            System.err.println("HSMDecryptEncrypt" + e);
//        }
//        return null;
//    }
//
//    public static byte[] decrypt(byte[] data, String keyAlias) throws Exception {
//        try {
//            KeyStore.PrivateKeyEntry encryptionKey = getKeyFromKeyStore(keyAlias);
//
//            if (data == null || data.length == 0) {
//                String errormsg = "byte array data can not be null or blank array.";
//                throw new Exception(errormsg);
//            }
//
//            ByteArraySpliter arrSpliter = new ByteArraySpliter(data);
//
//            byte[] secretKey = decryptSecretKeyData(arrSpliter.getEncryptedSecretKey(), arrSpliter.getIv(), encryptionKey.getPrivateKey());
//
//            byte[] plainData = decryptData(arrSpliter.getEncryptedData(), arrSpliter.getIv(), secretKey);
//
//            boolean result = validateHash(plainData);
//            if (!result) {
//                String errormsg = "Integrity Validation Failed : " + "The original data at client side and the decrypted data at server side is not identical";
//                throw new Exception(errormsg);
//            }
//            return trimHMAC(plainData);
//        } catch (Exception e) {
//            System.err.println("HSMDecryptEncrypt" + e);
//        }
//        return null;
//    }
//
//    private static byte[] decryptSecretKeyData(byte[] encryptedSecretKey, byte[] iv, PrivateKey privateKey) throws Exception {
//
//        try {
//
//            Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding");
//            // Cipher rsaCipher = Cipher.getInstance("RSA/ECB/NoPadding", p11Provider);
//            rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
//            int keyLength = 2048;
//
//            byte[] paddedPlainText = rsaCipher.doFinal(encryptedSecretKey);
//            /* Ensure leading zeros not stripped */
//            if (paddedPlainText.length < keyLength / 8) {
//                byte[] tmp = new byte[keyLength / 8];
//                System.arraycopy(paddedPlainText, 0, tmp, tmp.length - paddedPlainText.length, paddedPlainText.length);
//                System.out.println("Zero padding to " + (keyLength / 8));
//                paddedPlainText = tmp;
//            }
//            PSource pSrc = (new PSource.PSpecified(iv));
//            OAEPParameterSpec paramSpec = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA256, pSrc);
//            RSAPadding padding = RSAPadding.getInstance(RSAPadding.PAD_OAEP_MGF1, keyLength / 8, new SecureRandom(), paramSpec);
//            byte[] decryptedData = padding.unpad(paddedPlainText);
//            rsaCipher = null;
//            return decryptedData;
//        } catch (GeneralSecurityException e) {
//            System.err.println("HSMDecryptEncrypt" + e);
//            String errormsg = "Failed to decrypt AES secret key using RSA.";
//            throw new Exception(errormsg, e);
//        }
//    }
//
//    private static byte[] decryptData(byte[] encryptedData, byte[] eid, byte[] secretKey) throws Exception {
//        try {
//            byte[][] iv = split(eid, VECTOR_SIZE);
//
//            BufferedBlockCipher cipher = new BufferedBlockCipher(new CFBBlockCipher(new AESEngine(), BLOCK_SIZE));
//            KeyParameter key = new KeyParameter(secretKey);
//
//            cipher.init(false, new ParametersWithIV(key, iv[0]));
//            int outputSize = cipher.getOutputSize(encryptedData.length);
//            byte[] result = new byte[outputSize];
//            int processLen = cipher.processBytes(encryptedData, 0, encryptedData.length, result, 0);
//            cipher.doFinal(result, processLen);
//            return result;
//        } catch (InvalidCipherTextException txtExp) {
//            System.err.println("HSMDecryptEncrypt" + txtExp);
//            String errormsg = "Decrypting data using AES failed";
//            throw new Exception(errormsg, txtExp);
//        }
//    }
//
//    private static byte[] trimHMAC(byte[] decryptedText) {
//        byte[] actualText;
//        if (decryptedText == null || decryptedText.length <= HMAC_SIZE) {
//            actualText = new byte[0];
//        } else {
//            actualText = new byte[decryptedText.length - HMAC_SIZE];
//            System.arraycopy(decryptedText, HMAC_SIZE, actualText, 0,
//                    actualText.length);
//        }
//        return actualText;
//    }
//
//    private static byte[][] split(byte[] src, int n) {
//        byte[] l, r;
//        if (src == null || src.length <= n) {
//            l = src;
//            r = new byte[0];
//        } else {
//            l = new byte[n];
//            r = new byte[src.length - n];
//            System.arraycopy(src, 0, l, 0, n);
//            System.arraycopy(src, n, r, 0, r.length);
//        }
//        return new byte[][]{l, r};
//    }
//
//    private static boolean validateHash(byte[] decryptedText) throws Exception {
//        byte[][] hs = split(decryptedText, HMAC_SIZE);
//        try {
//
//            byte[] actualHash = generateHash(hs[1]);
//            if (new String(hs[0], "UTF-8").equals(new String(actualHash, "UTF-8"))) {
//                return true;
//            } else {
//                return false;
//            }
//        } catch (Exception he) {
//            String errormsg = "Not able to compute hash.";
//            System.err.println("HSMDecryptEncrypt" + he);
//            throw new Exception(errormsg, he);
//        }
//    }
//
//    public static byte[] generateHash(byte[] message) throws Exception {
//        byte[] hash = null;
//        try {
//            MessageDigest digest = MessageDigest.getInstance(DIGEST_ALGORITHM);
//            digest.reset();
//            hash = digest.digest(message);
//        } catch (GeneralSecurityException e) {
//            System.err.println("HSMDecryptEncrypt" + e);
//            String errormsg = "SHA-256 Hashing algorithm not available";
//            throw new Exception(errormsg);
//        }
//        return hash;
//    }
//
//    private static class ByteArraySpliter {
//
//        private final byte[] headerVersion;
//        private final byte[] iv;
//        private final byte[] encryptedSecretKey;
//        private final byte[] encryptedData;
//        private final byte[] publicKeyData;
//
//        public ByteArraySpliter(byte[] data) throws Exception {
//            int offset = 0;
//            headerVersion = new byte[HEADER_DATA.length];
//            copyByteArray(data, 0, headerVersion.length, headerVersion);
//            offset = offset + HEADER_DATA.length;
//            publicKeyData = new byte[PUBLIC_KEY_SIZE];
//            copyByteArray(data, offset, publicKeyData.length, publicKeyData);
//            offset = offset + PUBLIC_KEY_SIZE;
//            iv = new byte[EID_SIZE];
//            copyByteArray(data, offset, iv.length, iv);
//            offset = offset + EID_SIZE;
//            encryptedSecretKey = new byte[SECRET_KEY_SIZE];
//            copyByteArray(data, offset, encryptedSecretKey.length, encryptedSecretKey);
//            offset = offset + SECRET_KEY_SIZE;
//            encryptedData = new byte[data.length - offset];
//            copyByteArray(data, offset, encryptedData.length, encryptedData);
//        }
//
//        public byte[] getIv() {
//            return iv;
//        }
//
//        public byte[] getEncryptedSecretKey() {
//            return encryptedSecretKey;
//        }
//
//        public byte[] getEncryptedData() {
//            return encryptedData;
//        }
//
//        private void copyByteArray(byte[] src, int offset, int length, byte[] dest) throws Exception {
//            try {
//                System.arraycopy(src, offset, dest, 0, length);
//            } catch (Exception e) {
//                String errormsg = "Decryption failed, Corrupted packet";
//                throw new Exception(errormsg, e);
//            }
//        }
//    }
//
//    public static void main(String[] args) {
//        try {
//            String pfxFilePath = "D:\\env\\eSign\\Test-Class3DocumentSigner2014.pfx";
//            String pfxPassword = "emudhra";
//            String keyAlias = "1";
//            KeyStore keyStore = KeyStore.getInstance("PKCS12");
//            try (FileInputStream fis = new FileInputStream(pfxFilePath)) {
//                keyStore.load(fis, pfxPassword.toCharArray());
//            }
////            byte[] encryptedData = encryptData("abc".getBytes(), pfxFilePath, pfxPassword, keyAlias);
////            System.out.println("Encrypted Data: " + new String(encryptedData));
//            // Decrypt the data
//            byte[] encryptedData = Base64.getDecoder().decode("Xl8iMMGdVVXes2NSADlKJaU4AQILrm2CVc6fzo46ZmI8al4TKNhqle7dRAWstO7mOxLUQK82LUeHDZXaaMWg+gvIdoDA3j3VF0Q/On6fgXyrKfDXyt67LS2/R3+FSuq+ajAVso61k8xTx0Ro4oGyJhiZwc0mXO/HVkEFhgFpK5TX05UQQjz0UtBpmGMD96nccFFCvr7gQCH+9h8vq9af4SlqKkHLdafyc8zzmhwUKzDyOLHHBZwd6ZgbY9tyuuN8NUX9EiUQoSpi3kzGrnsohpcc/Z8fxVeougxWq4b0jTz6nXUnBf8TGkhi1HaPUqj0IAGpdCEygvumAx4QgYoNNw==");
//            byte[] decryptedData = decrypt(encryptedData, keyAlias);
//            String decryptedText = new String(decryptedData);
//            System.out.println("Decrypted Data: " + decryptedText);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//    }
//
//    public static byte[] encryptData(byte[] randomData, String pfxFilePath, String pfxPassword, String recipientKeyAlias)
//            throws KeyStoreException, NoSuchAlgorithmException, CertificateException, IOException,
//            UnrecoverableKeyException, InvalidKeyException, Exception {
//        KeyStore keyStore = KeyStore.getInstance("PKCS12");
//        FileInputStream fis = new FileInputStream(pfxFilePath);
//        char[] password = pfxPassword.toCharArray();
//        keyStore.load(fis, password);
//        X509Certificate recipientCert = (X509Certificate) keyStore.getCertificate(recipientKeyAlias);
//        PublicKey recipientPublicKey = recipientCert.getPublicKey();
//        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
//        cipher.init(Cipher.ENCRYPT_MODE, recipientPublicKey);
//        byte[] encryptedData = cipher.doFinal(randomData);
//        return encryptedData;
//    }
//
//}
