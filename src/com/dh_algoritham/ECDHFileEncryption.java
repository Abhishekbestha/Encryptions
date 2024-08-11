package com.dh_algoritham;

import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import javax.xml.bind.DatatypeConverter;
import static javax.xml.bind.DatatypeConverter.printHexBinary;
import org.apache.commons.codec.binary.Base64;

public class ECDHFileEncryption {

    public static void main(String[] args) throws Exception {
        System.out.println("Enter number 1(encrypt) or 2(decrypt): ");
        Scanner obj = new Scanner(System.in);
        int i = obj.nextInt();
        switch (i) {
            case 1:
                System.out.println("Enter file path to encrypt: ");
                obj.nextLine(); // Consume the newline character left by nextInt()
                String filePath = obj.nextLine().replaceAll("^\"|\"$", "");
                Path path = Paths.get(filePath.trim());
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
                System.out.println("\n\nFile Encrypted and saved Successfully.");
                break;
            case 2:
                System.out.println("Enter file path to decrypt: ");
                obj.nextLine(); // Consume the newline character left by the previous input
                String decryptPath = obj.nextLine().replaceAll("^\"|\"$", "");
                Path filePathDecrypt = Paths.get(decryptPath.trim());
                byte[] fileRead = Files.readAllBytes(filePathDecrypt);
                System.out.println("Enter sharedKey to decrypt: ");
                String sharedSecretKey = obj.next();
                System.out.println("Enter filename: ");
                String filename = obj.next();
                byte[] finalData = Base64.decodeBase64(fileRead);
                desc(fileRead, sharedSecretKey, filename);
                System.out.println("\n\nFile Decrypted and saved Successfully.");
                break;
            default:
                throw new Exception();
        }
    }

    public static byte[] generateECDH() throws Exception {
        // Generate ephemeral ECDH keypair
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(256);
        KeyPair kp = kpg.generateKeyPair();
        byte[] ourPk = kp.getPublic().getEncoded();

        // Display our public key
        System.out.println("Public Key: " + Base64.encodeBase64String(ourPk));

        byte[] otherPk = Base64.decodeBase64(Base64.encodeBase64String(ourPk));
        KeyFactory kf = KeyFactory.getInstance("EC");
        X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
        PublicKey otherPublicKey = kf.generatePublic(pkSpec);

        // Perform key agreement
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(kp.getPrivate());
        ka.doPhase(otherPublicKey, true);

        // Read shared secret
        byte[] sharedSecret = ka.generateSecret();
//        String sharedenc = Base64.encodeBase64String(sharedSecret);
        String sharedenc = printHexBinary(sharedSecret);
        System.out.println("Shared secret: " + sharedenc);
        return sharedSecret;
    }

    public static byte[] enc(byte[] data, byte[] sharedSecret, String fileName, String extension) throws Exception {
        byte[] encryptedData = null;
        try {
            byte[] raw = sharedSecret;
            Key key = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] ivByte = new byte[cipher.getBlockSize()];
            IvParameterSpec ivParamsSpec = new IvParameterSpec(ivByte);
            cipher.init(1, key, ivParamsSpec);
            encryptedData = cipher.doFinal(data);

//            String encData = Base64.encodeBase64String(encryptedData);
//            System.out.println(encData);
            String fileStorePath = System.getProperty("user.dir") + File.separator + "Files";
            File folder = new File(fileStorePath);
            String storeData = fileName + "_" + printHexBinary(sharedSecret) + "_" + extension;
            if (!folder.exists()) {
                boolean result = folder.mkdirs();
                if (result) {
                    Files.write(Paths.get(fileStorePath + File.separator + storeData), encryptedData);
//                    Files.write(Paths.get(fileStorePath + File.separator + "Shared_key.txt"), storeData.getBytes());
                } else {
                    System.out.println("Failed to create folder.");
                }
            } else {
                Files.write(Paths.get(fileStorePath + File.separator + storeData), encryptedData);
//                Files.write(Paths.get(fileStorePath + File.separator + "Shared_key.txt"), storeData.getBytes());
            }
        } catch (Exception ex) {
            ex.printStackTrace();
        }
        return encryptedData;
    }

    public static byte[] desc(byte[] data, String secretBytes, String filename) throws Exception {
        try {
//            byte[] sharedSecretBytes = Base64.decodeBase64(secretBytes);
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
            return decryptedData;
        } catch (Exception ex) {
            throw ex;
        }
    }

}
