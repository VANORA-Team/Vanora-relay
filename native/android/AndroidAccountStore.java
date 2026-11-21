package org.vanora.relay;

import android.content.Context;
import android.security.keystore.KeyGenParameterSpec;
import android.security.keystore.KeyProperties;
import android.util.AtomicFile;
import java.io.File;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyStore;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import mobile.Store;

/** Supply one instance per account profile when constructing the mobile.Client. Requires API 23+. */
public final class AndroidAccountStore implements Store {
    private final String alias;
    private final AtomicFile storage;

    public AndroidAccountStore(Context context, String profile) {
        if (!profile.matches("[a-zA-Z0-9_-]{1,64}")) throw new IllegalArgumentException("Invalid profile");
        alias = "org.vanora.relay." + profile;
        storage = new AtomicFile(new File(context.getNoBackupFilesDir(), alias));
    }

    private SecretKey key(boolean create) throws Exception {
        KeyStore vault = KeyStore.getInstance("AndroidKeyStore");
        vault.load(null);
        SecretKey key = (SecretKey) vault.getKey(alias, null);
        if (key != null) return key;
        if (!create) throw new IllegalStateException("Missing Android Keystore key");
        KeyGenerator gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, "AndroidKeyStore");
        gen.init(new KeyGenParameterSpec.Builder(alias,
            KeyProperties.PURPOSE_ENCRYPT | KeyProperties.PURPOSE_DECRYPT)
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(256).build());
        return gen.generateKey();
    }

    @Override public synchronized String load() throws Exception {
        final byte[] blob;
        try { blob = storage.readFully(); }
        catch (java.io.FileNotFoundException e) {
            if (storage.getBaseFile().exists()) throw e;
            return "";
        }
        if (blob.length < 28) throw new IllegalStateException("Invalid account record");
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.DECRYPT_MODE, key(false), new GCMParameterSpec(128, Arrays.copyOf(blob, 12)));
        return new String(aes.doFinal(blob, 12, blob.length - 12), StandardCharsets.UTF_8);
    }

    @Override public synchronized void save(String value) throws Exception {
        Cipher aes = Cipher.getInstance("AES/GCM/NoPadding");
        aes.init(Cipher.ENCRYPT_MODE, key(!storage.getBaseFile().exists()));
        byte[] iv = aes.getIV();
        if (iv.length != 12) throw new IllegalStateException("Unexpected Android Keystore IV length");
        byte[] ciphertext = aes.doFinal(value.getBytes(StandardCharsets.UTF_8));
        FileOutputStream out = storage.startWrite();
        try {
            out.write(iv);
            out.write(ciphertext);
            storage.finishWrite(out);
        } catch (Exception failure) {
            storage.failWrite(out);
            throw failure;
        }
    }
}
