package com.dh_algoritham;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;
import java.util.logging.Level;
import java.util.logging.Logger;
import javax.crypto.spec.IvParameterSpec;
import org.apache.commons.codec.binary.Base64;

public class DHSecurity {

    public static void main(String[] args) {
        try {

            // Generate ephemeral ECDH keypair
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(256);
            KeyPair kp = kpg.generateKeyPair();
            byte[] ourPk = kp.getPublic().getEncoded();

            // Display our public key
            System.out.println("Public Key: " + Base64.encodeBase64String(ourPk));
            Scanner sc = new Scanner(System.in);
            System.out.println("Enter Public Key:");
//            String publickeyfrom = URLDecoder.decode(sc.nextLine(), StandardCharsets.UTF_8.name());
            String publickeyfrom = sc.nextLine();
//                    "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEN8bxWUo+Vmx/WcK7dHmQZH4uWq8moX8dwAhFV/i4FzHX0Ds3O/63YStNXxjqEvgkIXNa0VW+wa/YRL3fsH06uQ==";
            // Read other's public key:
            byte[] otherPk = Base64.decodeBase64(publickeyfrom);
            KeyFactory kf = KeyFactory.getInstance("EC");
            X509EncodedKeySpec pkSpec = new X509EncodedKeySpec(otherPk);
            PublicKey otherPublicKey = kf.generatePublic(pkSpec);

            // Perform key agreement
            KeyAgreement ka = KeyAgreement.getInstance("ECDH");
            ka.init(kp.getPrivate());
            ka.doPhase(otherPublicKey, true);

            // Read shared secret
            byte[] sharedSecret = ka.generateSecret();
//            String shared = printHexBinary(sharedSecret);
//            System.out.println("Shared secret: " + shared);
            String sharedSecretStr = Base64.encodeBase64String(sharedSecret);
            System.out.println(sharedSecretStr);
//            String sharedSecretStr = DatatypeConverter.printHexBinary(sharedSecret);
//            System.out.println("Shared secret: " + sharedSecretStr);

            // Derive a key from the shared secret and both public keys
//            MessageDigest hash = MessageDigest.getInstance("SHA-256");
//            hash.update(sharedSecret);
//            // Simple deterministic ordering
//            List<ByteBuffer> keys = Arrays.asList(ByteBuffer.wrap(ourPk), ByteBuffer.wrap(otherPk));
//            Collections.sort(keys);
//            hash.update(keys.get(0));
//            hash.update(keys.get(1));
////
//            byte[] derivedKey = hash.digest();
//            String finalKey = printHexBinary(derivedKey);
//            System.out.println("Final key: " + finalKey);
//            String publicKey ="MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEsX0tJDu3AV/Kv6+1ZjwSD7fEq1WzoniGcSwqNpZBOW5gPSMW7Chq9Dt2K3GODipQwBTTVyL9lNIN6rGxnbdFuA==";
            System.out.println("Enter data to encrypt:");
            String encDataStr = sc.nextLine();
            byte[] encData = encDataStr.getBytes();
            DHSecurity sec = new DHSecurity();
//            byte[] encData1 = Base64.decodeBase64("PPscY5bNCtcCO1RR9HcO1QE0kl4VbkG5Gv0DOj1d9J0fC4omTpQbROj+ATEqfBF7");
            byte[] encData1 = sec.enc(encData, sharedSecret);
            System.out.println("Enc:" + Base64.encodeBase64String(encData1));
//            System.out.println("Enter enc data:");
            System.out.println("Enter data to decrypt:");
//            String encDataStr = sc.nextLine();
            byte[] encDataInput = Base64.decodeBase64(sc.nextLine());
            byte[] decData = sec.desc(encDataInput, sharedSecretStr);
            System.out.println("dec val:" + new String(decData));
            System.out.println("dec base64:" + Base64.encodeBase64String(decData));
        } catch (Exception ex) {
            Logger.getLogger(DHSecurity.class.getName()).log(Level.SEVERE, null, ex);
        }
    }

    public byte[] enc(byte[] data, byte[] sharedSecret) throws Exception {
        try {
//            Security.addProvider(new BouncyCastleFipsProvider());
            byte[] raw = sharedSecret;
            Key key = new SecretKeySpec(raw, "AES");
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] ivByte = new byte[cipher.getBlockSize()];
            IvParameterSpec ivParamsSpec = new IvParameterSpec(ivByte);
            cipher.init(1, key, ivParamsSpec);

            byte[] encryptedData = cipher.doFinal(data);
            return encryptedData;
        } catch (Exception ex) {
            throw ex;
        }
    }

    public byte[] desc(byte[] data, String secretBytes) throws Exception {
        try {
//            Security.addProvider(new BouncyCastleFipsProvider());
//            byte[] decodedSharedSecret = DatatypeConverter.parseHexBinary(secretBytes);
            byte[] decodedSharedSecret = Base64.decodeBase64(secretBytes);
//String sharedSecretUtf8 = new String(decodedSharedSecret, StandardCharsets.UTF_8);
//System.out.println("Shared secret (UTF-8): " + sharedSecretUtf8);
            byte[] raw = decodedSharedSecret;
            Key key = new SecretKeySpec(raw, "AES");
//            AES/ECB/NoPadding
            Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            byte[] ivByte = new byte[cipher.getBlockSize()];
            IvParameterSpec ivParamsSpec = new IvParameterSpec(ivByte);
//            SecretKey bobsecret = new SecretKeySpec(secretBytes, 0, 16, "AES");
            cipher.init(Cipher.DECRYPT_MODE, key, ivParamsSpec);
            byte[] decryptedData = cipher.doFinal(data);
            return decryptedData;
        } catch (Exception ex) {
            throw ex;
        }
    }
}
