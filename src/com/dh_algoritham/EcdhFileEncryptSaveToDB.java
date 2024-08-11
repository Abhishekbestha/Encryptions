package com.dh_algoritham;

import Utilities.MysqlAccess;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.Key;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PublicKey;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Blob;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import static javax.xml.bind.DatatypeConverter.printHexBinary;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author 21701
 */
public class EcdhFileEncryptSaveToDB {

    private static MysqlAccess mysqlAccess = new MysqlAccess("pi", "bestha");

    public static void saveData(byte[] data, String sharedKey, String fileName) throws Exception {
        try {
            String insertQuery = "INSERT INTO `encfile`(`filestorage`,`sharedkey`,`filename`)VALUES(?,?,?)";
            ByteArrayInputStream inputStream = new ByteArrayInputStream(data);
            try (PreparedStatement preparedStatement = mysqlAccess.dataSourcePool.getConnection().prepareStatement(insertQuery)) {
                preparedStatement.setBlob(1, inputStream);
                preparedStatement.setString(2, sharedKey);
                preparedStatement.setString(3, fileName);
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

    public static Map<String, String> getData(int id) throws Exception {
        Map<String, String> map = new HashMap<>();
        byte[] byteArray = null;
        String b64 = null;
        try {
            String selectQuery = "SELECT * FROM encfile WHERE id=?";
            PreparedStatement preparedStatement = mysqlAccess.dataSourcePool.getConnection().prepareStatement(selectQuery);
            preparedStatement.setInt(1, id);
            ResultSet resultSet = preparedStatement.executeQuery();

            if (resultSet.next()) {
                Blob data = resultSet.getBlob("filestorage");

                try (InputStream inputStream = data.getBinaryStream()) {
                    ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
                    byte[] buffer = new byte[4096];

                    int bytesRead;
                    while ((bytesRead = inputStream.read(buffer)) != -1) {
                        outputStream.write(buffer, 0, bytesRead);
                    }

                    byteArray = outputStream.toByteArray();
                    b64 = Base64.encodeBase64String(byteArray);
                } catch (Exception e) {
                    e.printStackTrace();
                }

                String sharedkey = resultSet.getString("sharedkey");
                String filename = resultSet.getString("filename");

                map.put("data", b64);
                map.put("sharedkey", sharedkey);
                map.put("filename", filename);
            }
        } catch (SQLException e) {
            e.printStackTrace();
        }
        return map;
    }

    private static byte[] generateECDH() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        byte[] ourPk = kp.getPublic().getEncoded();
        System.out.println("Public Key: " + Base64.encodeBase64String(ourPk));
        byte[] otherPk = Base64.decodeBase64(Base64.encodeBase64String(ourPk));
        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
        PublicKey otherPublicKey = kf.generatePublic(pkSpec);
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(otherPublicKey, true);
        byte[] sharedSecret = ka.generateSecret();
        String sharedenc = printHexBinary(sharedSecret);
        System.out.println("Shared secret: " + sharedenc);
        return sharedSecret;
    }

    private static byte[] enc(byte[] data, byte[] sharedSecret, String fileName, String extension) throws Exception {
        byte[] encryptedData = null;
        try {
            byte[] raw = sharedSecret;
            Key key = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] ivByte = new byte[cipher.getBlockSize()];
            IvParameterSpec ivParamsSpec = new IvParameterSpec(ivByte);
            cipher.init(1, key, ivParamsSpec);
            encryptedData = cipher.doFinal(data);
            String encData = Base64.encodeBase64String(encryptedData);
            String Sharedkey = printHexBinary(sharedSecret);
            saveData(encryptedData, Sharedkey, fileName + "." + extension);
            System.out.println("\n\nFile Encrypted and saved Successfully.");
        } catch (Exception ex) {
            System.out.println(ex);
        }
        return encryptedData;
    }

    private static void desc(byte[] data, String secretBytes, String filename) throws Exception {
        try {
            byte[] sharedSecretBytes = DatatypeConverter.parseHexBinary(secretBytes);
            byte[] raw = sharedSecretBytes;
            Key key = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] ivByte = new byte[cipher.getBlockSize()];
            IvParameterSpec ivParamsSpec = new IvParameterSpec(ivByte);
            cipher.init(Cipher.DECRYPT_MODE, key, ivParamsSpec);
            byte[] decryptedData = cipher.doFinal(data);
            String fileStorePath = System.getProperty("user.dir") + "/Files";
            File folder = new File(fileStorePath);
            if (!folder.exists()) {
                boolean result = folder.mkdirs();
                if (result) {
                    Files.write(Paths.get(fileStorePath + File.separator + filename), decryptedData);
                } else {
                    System.out.println("Failed to create folder.");
                }
            } else {
                Files.write(Paths.get(fileStorePath + File.separator + filename), decryptedData);
            }
            System.out.println("Saved: " + fileStorePath + File.separator + filename);
            System.out.println("\n\nFile Decrypted and saved Successfully.");
        } catch (Exception ex) {
            System.out.println(ex);
            throw ex;
        }
    }

    public static void main(String[] args) throws Exception {
        Scanner obj = new Scanner(System.in);
        System.out.println("Enter number 1(encrypt) or 2(decrypt): ");

        int i = obj.nextInt();
        switch (i) {
            case 1:
                System.out.println("Enter file path to encrypt: ");
                obj.nextLine();
                String filePath = obj.nextLine().replaceAll("^\"|\"$", "");
                Path path = Paths.get(filePath);
                byte[] encData = Files.readAllBytes(path);
                String extension = "";
                String fileNameWithExtension = path.getFileName().toString();
                String fileNameWithoutExtension = fileNameWithExtension.substring(0, fileNameWithExtension.lastIndexOf("."));
                // TO GET EXT OF FILE
                int dotIndex = fileNameWithExtension.lastIndexOf('.');
                if (dotIndex > 0 && dotIndex < fileNameWithExtension.length() - 1) {
                    extension = fileNameWithExtension.substring(dotIndex + 1);
                }

                System.out.println("File extension: " + extension + "\n");
                enc(encData, generateECDH(), fileNameWithoutExtension, extension);

                break;
            case 2:
                System.out.println("Enter id to decrypt: ");
                int id = Integer.parseInt(obj.next());
                Map<String, String> map = getData(id);
                String data = map.get("data");
                String sharedkey = map.get("sharedkey");
                String filename = map.get("filename");
                desc(Base64.decodeBase64(data), sharedkey, filename);
                break;

            default:
                throw new Exception();
        }
    }
}
