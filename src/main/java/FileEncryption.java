import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.*;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;

public class FileEncryption {

    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }

    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }
public static SecretKey getKeyFromPassword(String password, byte[] salt)
 throws NoSuchAlgorithmException, InvalidKeySpecException {
     SecretKeyFactory factory = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA256");
    KeySpec keySpec = new PBEKeySpec(password.toCharArray(), salt, 65536,256);
    return new SecretKeySpec(factory.generateSecret(keySpec).getEncoded(),"AES");
    }

public static byte[] generateSalt(){
    byte[] salt = new byte[16];
    new SecureRandom().nextBytes(salt);
    return salt;
}
    public static void encryptOrDecryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                            File inputFile, File outputFile, int cipherMode)
            throws IOException, NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        //cipher.ENCRYPT.MODE has a constant value of one, while cipher.DECRYPT.MODE has a constant value of 2
        cipher.init(cipherMode, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }

        inputStream.close();
        outputStream.close();
    }
}
