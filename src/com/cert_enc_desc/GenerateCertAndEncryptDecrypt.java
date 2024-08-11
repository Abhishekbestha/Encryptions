package com.cert_enc_desc;

import java.io.File;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.Cipher;

public class GenerateCertAndEncryptDecrypt {

    private static String BASE_PATH = Paths.get(System.getProperty("user.dir"), "Files", "Resources").toString();
    private static String CERTIFICATE = BASE_PATH + File.separator + "1.cer";

    public static void main(String[] args) throws Exception {
        Scanner scanner = new Scanner(System.in);

        // Load certificate
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        X509Certificate cert = (X509Certificate) cf.generateCertificate(new FileInputStream(CERTIFICATE));

        // Generate key pair
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048); // key size
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        // Encrypt data with public key and OAEP padding (recommended over PKCS1Padding for security)
        Cipher cipher = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding"); // Use OAEP padding
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        System.out.print("Enter your data to encrypt: ");
        String inputData = scanner.nextLine();
        byte[] encryptedData = cipher.doFinal(inputData.getBytes());
        System.out.println("\nEncrypted data: " + Base64.getEncoder().encodeToString(encryptedData));
        System.out.println("\nPublicKey: " + Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded()));

        // Decrypt data with private key and OAEP padding
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = cipher.doFinal(encryptedData);
        System.out.println("\nDecrypted data: " + new String(decryptedData));
        System.out.println("\nPrivateKey: " + Base64.getEncoder().encodeToString(keyPair.getPrivate().getEncoded()));
    }
}
