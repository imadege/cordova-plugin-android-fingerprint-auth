package com.cordova.plugin.android.fingerprintauth;

import android.content.Context;
import android.util.Log;

import android.security.KeyPairGeneratorSpec;

import java.math.BigInteger;
import java.security.Key;
import java.security.KeyPairGenerator;
import java.security.KeyPair;
import java.security.KeyStore;
import java.util.Calendar;
import java.security.cert.Certificate;

import javax.crypto.Cipher;
import javax.security.auth.x500.X500Principal;
import android.util.Base64;

public class POkey {
    private static final String KEYSTORE_PROVIDER = "AndroidKeyStore";
    private static final String CIPHER = "RSA/ECB/PKCS1Padding";

    public static byte[] encrypt(byte[] buf, String alias) throws Exception {
        Cipher cipher = createCipher(Cipher.ENCRYPT_MODE, alias);
        return cipher.doFinal(buf);
    }

    public static byte[] decrypt(byte[] encrypted, String alias) throws Exception {
        Cipher cipher = createCipher(Cipher.DECRYPT_MODE, alias);
        return cipher.doFinal(encrypted);
    }

    public static void createKeyPair(Context ctx, String alias) throws Exception {
        Calendar notBefore = Calendar.getInstance();
        Calendar notAfter = Calendar.getInstance();
        notAfter.add(Calendar.YEAR, 100);
        String principalString = String.format("CN=%s, OU=%s", alias, ctx.getPackageName());
        KeyPairGeneratorSpec spec = new KeyPairGeneratorSpec.Builder(ctx)
                .setAlias(alias)
                .setSubject(new X500Principal(principalString))
                .setSerialNumber(BigInteger.ONE)
                .setStartDate(notBefore.getTime())
                .setEndDate(notAfter.getTime())
                .setEncryptionRequired()
                .setKeySize(2048)
                .setKeyType("RSA")
                .build();
        KeyPairGenerator kpGenerator = KeyPairGenerator.getInstance("RSA", KEYSTORE_PROVIDER);
        kpGenerator.initialize(spec);
        kpGenerator.generateKeyPair();
    }

    public static Cipher createCipher(int cipherMode, String alias) throws Exception {
        KeyStore.PrivateKeyEntry keyEntry = getKeyStoreEntry(alias);
        if (keyEntry == null) {
            throw new Exception("Failed to load key for " + alias);
        }
        Key key;
        switch (cipherMode) {
            case Cipher.ENCRYPT_MODE:
                key = keyEntry.getCertificate().getPublicKey();
                break;
            case  Cipher.DECRYPT_MODE:
                key = keyEntry.getPrivateKey();
                break;
            default : throw new Exception("Invalid cipher mode parameter");
        }
        Cipher cipher = Cipher.getInstance(CIPHER);
        cipher.init(cipherMode, key);
        return cipher;
    }


    public static String KeyCertificate(String ALIAS){
        String cert = "No cert";
        try{
            Certificate r = POkey.getCert(ALIAS);
            //get encoded version
            cert = POkey.BytestoString(r.getEncoded());

        }catch (Exception e){
            cert = "Missing certificate";
        }
        return cert;
    }
    public static Certificate  getCert(String alias) throws  Exception{
        KeyStore.PrivateKeyEntry keyEntry = getKeyStoreEntry(alias);
        if (keyEntry == null) {
            throw new Exception("Failed to load key for " + alias);
        }
        return keyEntry.getCertificate();

    }

    public static boolean isEntryAvailable(String alias) {
        try {
            return getKeyStoreEntry(alias) != null;
        } catch (Exception e) {
            return false;
        }
    }



    public static String BytestoString(byte[] response){
        return Base64.encodeToString(response, Base64.DEFAULT);
    }

    private static KeyStore.PrivateKeyEntry getKeyStoreEntry(String alias) throws Exception {
        KeyStore keyStore = KeyStore.getInstance(KEYSTORE_PROVIDER);
        keyStore.load(null, null);
        return (KeyStore.PrivateKeyEntry) keyStore.getEntry(alias, null);
    }





}
