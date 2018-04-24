package com.arioliving.ccm;

import com.facebook.react.uimanager.*;
import com.facebook.react.bridge.*;
import com.facebook.systrace.Systrace;
import com.facebook.systrace.SystraceMessage;
import com.facebook.react.ReactInstanceManager;
import com.facebook.react.ReactRootView;
import com.facebook.react.modules.core.DefaultHardwareBackBtnHandler;
import com.facebook.react.modules.core.DeviceEventManagerModule;
import com.facebook.react.shell.MainReactPackage;
import com.facebook.soloader.SoLoader;

import android.content.Context;
import android.os.Bundle;
import android.util.Log;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Provider;
import java.security.Security;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.spongycastle.jce.provider.BouncyCastleProvider;

public class AndroidAESCCMModule extends ReactContextBaseJavaModule {

    public static final Integer TAG_SIZE = 32;

    private static Boolean mKeyIsSet = false;
    private static byte[] mKey;
    private static Cipher mAesCipher;

    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    //Constructor
    public AndroidAESCCMModule(ReactApplicationContext reactContext) {
        super(reactContext);

        try {
            mAesCipher = Cipher.getInstance("AES/CCM/NoPadding", "SC");
        } catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        } catch (NoSuchProviderException e) {
            e.printStackTrace();
        } catch (NoSuchPaddingException e) {
            e.printStackTrace();
        }

    }

    @Override
    public String getName() {
        return "AndroidAESCCMModule";
    }

    @ReactMethod
    public void setKey(ReadableArray key) {
        for (int i = 0; i < key.size(); i++) {
            mKey[i] = (byte) key.getInt(i);
        }
        mKeyIsSet = true;
    }

    @ReactMethod
    public void decrypt(ReadableArray aad, ReadableArray encrypted, ReadableArray nonce, ReadableArray tag, Promise promise) {
        if (!mKeyIsSet || nonce.size() == 0 || tag.size() != (TAG_SIZE / 8)) {
            promise.reject("Key not set / No nonce");
        }

        byte[] aadBytes = new Byte(aad.size());
        byte[] encryptedBytes = new Byte(clear.size());
        byte[] nonceBytes = new Byte(nonce.size());
        byte[] tagBytes = new Byte(tag.size());
        byte[] clear;

        for (int i = 0; i < aad.size(); i++) {
            aadBytes[i] = (byte) aad.getInt(i);
        }
        for (int i = 0; i < encrypted.size(); i++) {
            encryptedBytes[i] = (byte) encrypted.getInt(i);
        }
        for (int i = 0; i < nonce.size(); i++) {
            nonceBytes[i] = (byte) nonce.getInt(i);
        }
        for (int i = 0; i < tag.size(); i++) {
            tagBytes[i] = (byte) tag.getInt(i);
        }
        
        try {
            SecretKeySpec skeySpec = new SecretKeySpec(mKey, "AES");
            GCMParameterSpec ccmSpec = new GCMParameterSpec(TAG_SIZE, nonceBytes);
            mAesCipher.init(Cipher.DECRYPT_MODE, skeySpec, ccmSpec);
            mAesCipher.updateAAD(aadBytes);
            clear = mAesCipher.doFinal(encryptedBytes);
            promise.resolve(clear);
        } catch (InvalidKeyException e) {
            promise.reject("Invalid Key");
        } catch (InvalidAlgorithmParameterException e) {
            promise.reject("Invalid Algorithm");
        } catch (IllegalBlockSizeException e) {
            promise.reject("Invalid Block Size");
        } catch (BadPaddingException e) {
            promise.reject("Invalid Padding");
        } catch (AEADBadTagException e) {
            promise.reject("Invalid tag");
        }
    }

    @ReactMethod
    public void encrypt(ReadableArray aad, ReadableArray clear, ReadableArray nonce, Promise promise) {
        if (!mKeyIsSet || nonce.size() == 0) {
            promise.reject("Key not set / No nonce");
        }

        byte[] aadBytes = new Byte(aad.size());
        byte[] clearBytes = new Byte(clear.size());
        byte[] nonceBytes = new Byte(nonce.size());
        byte[] encrypted;

        for (int i = 0; i < aad.size(); i++) {
            aadBytes[i] = (byte) aad.getInt(i);
        }
        for (int i = 0; i < clear.size(); i++) {
            clearBytes[i] = (byte) clear.getInt(i);
        }
        for (int i = 0; i < nonce.size(); i++) {
            nonceBytes[i] = (byte) nonce.getInt(i);
        }

            try {
                SecretKeySpec skeySpec = new SecretKeySpec(mKey, "AES");
                GCMParameterSpec ccmSpec = new GCMParameterSpec(TAG_SIZE, nonceBytes);
                mAesCipher.init(Cipher.ENCRYPT_MODE, skeySpec, ccmSpec);
                mAesCipher.updateAAD(aadBytes);
                encrypted =mAesCipher.doFinal(clearBytes);
                promise.resolve(encrypted);
            } catch (InvalidKeyException e) {
                promise.reject("Invalid Key");
            } catch (InvalidAlgorithmParameterException e) {
                promise.reject("Invalid Algorithm");
            } catch (IllegalBlockSizeException e) {
                    promise.reject("Invalid Block Size");
            } catch (BadPaddingException e) {
                    promise.reject("Invalid Padding");
            }
    }

    // private final static char[] hexArray = "0123456789ABCDEF".toCharArray();

    // public static String bytesToHex(byte[] bytes) {
    //     char[] hexChars = new char[bytes.length * 2];
    //     for (int j = 0; j < bytes.length; j++) {
    //         int v = bytes[j] & 0xFF;
    //         hexChars[j * 2] = hexArray[v >>> 4];
    //         hexChars[j * 2 + 1] = hexArray[v & 0x0F];
    //     }
    //     return new String(hexChars);
    // }
}
