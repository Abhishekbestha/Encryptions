package com.digitalsignverify;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Scanner;

import javax.xml.bind.DatatypeConverter;
import org.apache.commons.codec.binary.Base64;

/**
 *
 * @author 21701
 */
public class DigitalSigningVerification {

    private static final String SIGNING_ALGORITHM = "SHA256withRSA";
    private static final String RSA = "RSA";
    private static Scanner sc;

    public static byte[] Create_Digital_Signature(byte[] input, PrivateKey Key) throws Exception {
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initSign(Key);
        signature.update(input);
        return signature.sign();
    }

    public static KeyPair Generate_RSA_KeyPair() throws Exception {
        SecureRandom secureRandom = new SecureRandom();
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(RSA);
        keyPairGenerator.initialize(2048, secureRandom);
        return keyPairGenerator.generateKeyPair();
    }

    public static boolean Verify_Digital_Signature(byte[] input, byte[] signatureToVerify, PublicKey key) throws Exception {
        Signature signature = Signature.getInstance(SIGNING_ALGORITHM);
        signature.initVerify(key);
        signature.update(input);
        return signature.verify(signatureToVerify);
    }

    public static void main(String args[]) throws Exception {
        String input = "3c2754f0202847d3b6b721a56232846b3b15e0273159af51910129d0354495c8";
        KeyPair keyPair = Generate_RSA_KeyPair();
        byte[] signature = Create_Digital_Signature(input.getBytes(), keyPair.getPrivate());
        System.out.println("Signature Value:\n " + DatatypeConverter.printHexBinary(signature));
        byte[] a = Base64.decodeBase64("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");
//        System.out.println("Verification: " + Verify_Digital_Signature("70ccde7b39253be49f9c95cc90ba080656be4040ff81acaa70e316639afbf09f".getBytes(), a, keyPair.getPublic()));
        System.out.println("Verification: " + Verify_Digital_Signature(input.getBytes(), signature, keyPair.getPublic()));
    }
}
