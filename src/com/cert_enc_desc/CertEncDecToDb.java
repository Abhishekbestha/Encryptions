package com.cert_enc_desc;

import Utilities.MysqlAccess;
import java.io.File;
import java.io.FileInputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.Cipher;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author abhi
 */
public class CertEncDecToDb {

    private static MysqlAccess mysqlAccess = new MysqlAccess("pi", "bestha");

    private static String BASE_PATH = System.getProperty("user.dir") + File.separator + "Files" + File.separator + "Resources" + File.separator;
    private static String CERTIFICATE = BASE_PATH + "1_EC.cer";
    private static String PFX = BASE_PATH + "Abhishek_RSA.pfx";
    private static String PFX_PASSWORD = "1";
    private static String PFX_ALIAS = "1";

    public static void main(String[] args) {
        try {
            KeyStore keyStore = KeyStore.getInstance("PKCS12");
            FileInputStream inputStream = new FileInputStream(PFX);
            keyStore.load(inputStream, PFX_PASSWORD.toCharArray());
            PrivateKey privateKey = (PrivateKey) keyStore.getKey(PFX_ALIAS, PFX_PASSWORD.toCharArray());
            PublicKey pKey = (PublicKey) keyStore.getCertificate(PFX_ALIAS).getPublicKey();
            FileInputStream inputStream1 = new FileInputStream(CERTIFICATE);
            CertificateFactory cf = CertificateFactory.getInstance("X509");
            X509Certificate crt = (X509Certificate) keyStore.getCertificate(PFX_ALIAS);
            PublicKey pKey1 = (PublicKey) crt.getPublicKey();
            System.out.println("Enter number 1(encrypt) or 2(decrypt): ");
            Scanner obj = new Scanner(System.in);
            String x1 = null;
            int i = obj.nextInt();
            switch (i) {
                case 1:
                    System.out.println("Enter your data to encrypt:");
                    obj.nextLine();
                    String text = obj.nextLine();
                    x1 = encrypt(text, pKey1);
                    System.out.println("Enter description:");
                    String description = obj.nextLine();
                    System.out.println("\nEncrypted Data:\t" + x1);
                    saveData(x1,description);
                    break;
                case 2:
                    System.out.println("Enter id to decrypt:");
                    obj.nextLine();
                    String id = obj.nextLine();
                    String textToDecrypt = selectData(id);
                    String x = decrypt(textToDecrypt, privateKey);
                    System.out.println("\nDecrypted Data:\t" + x);
                    break;
                default:
                    throw new AssertionError();
            }

        } catch (Exception ex) {
            Logger.getLogger(CertEncryptAndDecrypt.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public static String decrypt(String enc, PrivateKey privateKey) {
        try {
            Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
            cipher.init(Cipher.DECRYPT_MODE, privateKey);
            byte[] decryptedData = cipher.doFinal(Base64.decodeBase64(enc));
            return new String(decryptedData, StandardCharsets.UTF_8);
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

    public static void saveData(String data, String description) throws Exception {
        try {
            String insertQuery = "INSERT INTO `encdata`(`data`,`description`)VALUES(?,?)";
            try (PreparedStatement preparedStatement = mysqlAccess.dataSourcePool.getConnection().prepareStatement(insertQuery)) {
                preparedStatement.setString(1, data);
                preparedStatement.setString(2, description);
                int rowsAffected = preparedStatement.executeUpdate();
                if (rowsAffected > 0) {
                    System.out.println("Data inserted successfully.");
                } else {
                    System.out.println("Data insertion failed.");
                }
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
    }

    public static String selectData(String data) throws Exception {
        try {
            String selectQuery = "SELECT * FROM encdata WHERE description=?";
            PreparedStatement preparedStatement = mysqlAccess.dataSourcePool.getConnection().prepareStatement(selectQuery);
            preparedStatement.setString(1, data);

            ResultSet resultSet = preparedStatement.executeQuery();
            if (resultSet.next()) {
                String resultData = resultSet.getString("data");
                System.out.println("Data fetched successfully: " + resultData);
                return resultData;
            } else {
                System.out.println("No data found for id: " + data);
                return null;
            }
        } catch (SQLException e) {
            e.printStackTrace();
            throw new Exception("Error while selecting data", e);
        }
    }
}
