package com.cert_enc_desc;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.security.GeneralSecurityException;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;

/**
 *
 * @author 21701
 */
public class AadhaarEncDecKeyPair {

    private static String BASE_PATH = System.getProperty("user.dir") + File.separator + "Files" + File.separator + "Resources" + File.separator;
    private static String CERTIFICATE = BASE_PATH + "AadhaarEncrypter.cer";
    private static String PFX = BASE_PATH + "Test-Class3DocumentSigner2014.pfx";
    private static String PFX_PASSWORD = "emudhra";
    private static String PFX_ALIAS = "1";

    public static void main(String[] args) throws GeneralSecurityException, Exception {
        System.out.println("Enter Aadhaar Number to encrypt: ");
        Scanner obj = new Scanner(System.in);
        String aadhaarNo = obj.nextLine();
        String encData = AadhaarEncDecKeyPair.EncryptUsingPublicKey(aadhaarNo.getBytes());
        System.out.println("\nEncrypted Data:\t" + encData);
        System.out.println("\nDecrypted Data:\t" + AadhaarEncDecKeyPair.DecryptUsingPrivateKeyAsString(encData));
    }

    public static String EncryptUsingPublicKey(byte[] data) throws IOException, GeneralSecurityException, Exception {
        byte[] bytevalue = Files.readAllBytes(new File(CERTIFICATE).toPath());
        CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
        InputStream streamvalue = new ByteArrayInputStream(bytevalue);
        Certificate certificate = certificateFactory.generateCertificate(streamvalue);
        PublicKey publicKey = certificate.getPublicKey();
        Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        pkCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encSessionKey = pkCipher.doFinal(data);
        String b4encryptSkeyPkey = Base64.getEncoder().encodeToString(encSessionKey);
        return b4encryptSkeyPkey;
    }

    public static String DecryptUsingPrivateKeyAsString(String encryptedData) throws IOException, GeneralSecurityException {
        KeyStore keystore = KeyStore.getInstance("PKCS12");
        char[] password = PFX_PASSWORD.toCharArray();
        FileInputStream fis = new FileInputStream(PFX);
        keystore.load(fis, password);
        PrivateKey privateKey = (PrivateKey) keystore.getKey(PFX_ALIAS, password);
        Cipher pkCipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        pkCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decodedEncryptedData = Base64.getDecoder().decode(encryptedData);
        byte[] decryptedData = pkCipher.doFinal(decodedEncryptedData);
        return new String(decryptedData, StandardCharsets.UTF_8);
    }

}
