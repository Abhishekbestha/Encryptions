package com.cert_enc_desc;

import java.io.File;
import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author 20730
 */
public class CertEncryptAndDecrypt {

    private static String BASE_PATH = System.getProperty("user.dir") + File.separator + "Files" + File.separator + "Resources" + File.separator;
    private static String CERTIFICATE = BASE_PATH + "1.cer";
    private static String PFX = BASE_PATH + "Test-Class3DocumentSigner2014.pfx";
    private static String PFX_PASSWORD = "emudhra";
    private static String PFX_ALIAS = "1";

    public static void main(String[] args) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream inputStream = new FileInputStream(PFX);
            keyStore.load(inputStream, PFX_PASSWORD.toCharArray());
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(PFX_ALIAS, PFX_PASSWORD.toCharArray());
            PublicKey pKey = (PublicKey) keyStore.getCertificate(PFX_ALIAS).getPublicKey();
//            FileInputStream inputStream1 = new FileInputStream(CERTIFICATE);
//            CertificateFactory cf = CertificateFactory.getInstance("X509");
//            X509Certificate crt = (X509Certificate) cf.generateCertificate(inputStream1);
            X509Certificate crt = (X509Certificate) keyStore.getCertificate(PFX_ALIAS);
            PublicKey pKey1 = (PublicKey) crt.getPublicKey();
            Scanner obj = new Scanner(System.in);
            System.out.println("Enter your data to encrypt:");
            String text = obj.nextLine();
            String x1 = encrypt(text, pKey1);
            System.out.println("\nEncrypted Data:\t" + x1);
            String x = decrypt(x1, privateKey);
            System.out.println("\nDecrypted Data:\t" + x);
        } catch (Exception ex) {
            Logger.getLogger(CertEncryptAndDecrypt.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static String decrypt(String enc, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = cipher.doFinal(Base64.decodeBase64(enc));
            return new String(decryptedData);
        } catch (Exception ex) {
            ex.printStackTrace();
            Logger.getLogger(CertEncryptAndDecrypt.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }

    public static String encrypt(String test, PublicKey publicKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.ENCRYPT_MODE, publicKey);
            byte[] decryptedData = cipher.doFinal(test.getBytes());
            return Base64.encodeBase64String(decryptedData);
        } catch (Exception ex) {
            ex.printStackTrace();
            Logger.getLogger(CertEncryptAndDecrypt.class.getName()).log(Level.SEVERE, null, ex);
        }
        return null;
    }
}
