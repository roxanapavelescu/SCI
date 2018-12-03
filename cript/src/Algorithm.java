import java.io.UnsupportedEncodingException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.spec.SecretKeySpec;

import javax.xml.bind.DatatypeConverter;

public class Algorithm {

    private static SecretKeySpec secretKey;
    private static byte[] key;



    final protected static char[] hexArray = "0123456789ABCDEF".toCharArray();

    // Converts byte array to hex string
    // From: http://stackoverflow.com/questions/9655181/convert-from-byte-array-to-hex-string-in-java
    public static String bytesToHex(byte[] bytes) {
        char[] hexChars = new char[bytes.length * 2];
        for ( int j = 0; j < bytes.length; j++ ) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }


    public static void setKey(String myKey)
    {
        MessageDigest sha = null;
        try {
            key = myKey.getBytes("UTF-8");
            sha = MessageDigest.getInstance("SHA-1");
            key = sha.digest(key);
            key = Arrays.copyOf(key, 16);
            secretKey = new SecretKeySpec(key, "AES");
        }
        catch (NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        }
    }

    public static String AESencrypt(String strToEncrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            return Base64.getEncoder().encodeToString(cipher.doFinal(strToEncrypt.getBytes("UTF-8")));
        }
        catch (Exception e)
        {
            System.out.println("Error while encrypting: " + e.toString());
        }
        return null;
    }

    public static String AESdecrypt(String strToDecrypt, String secret)
    {
        try
        {
            setKey(secret);
            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5PADDING");
            cipher.init(Cipher.DECRYPT_MODE, secretKey);
            return new String(cipher.doFinal(Base64.getDecoder().decode(strToDecrypt)));
        }
        catch (Exception e)
        {
            System.out.println("Error while decrypting: " + e.toString());
        }
        return null;
    }

    public static void main(String[] args) throws Exception, BadPaddingException, IllegalBlockSizeException {
        final String secretKey = "ssshhhhhhhhhhh!!!!";

        String originalString = "howtodoinjava.com";
        String encryptedString = Algorithm.AESencrypt(originalString, secretKey) ;
        String decryptedString = Algorithm.AESdecrypt(encryptedString, secretKey) ;


        System.out.println("Start of AES");

        System.out.println("AES original string : " + originalString);
        System.out.println("AES encrypted string : " + encryptedString);
        System.out.println("AES decrypted string : " + decryptedString);





        System.out.println("Start of Blowfish");

        byte[] key	= "secret".getBytes();
        String IV  	= "12345678";

        System.out.println("KEY:\t " + bytesToHex(key));
        System.out.println("IV:\t " + bytesToHex(IV.getBytes()));

        SecretKeySpec keySpec = new SecretKeySpec(key, "Blowfish");
        String secret = "howtodoinjava.com";

        System.out.println("original Blowfish : "+ secret);
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");

        String out = null;
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, new javax.crypto.spec.IvParameterSpec(IV.getBytes()));
        byte[] encoding = cipher.doFinal(secret.getBytes());

        System.out.println("-- Encrypted Blowfish-----------");
        System.out.println("Base64:\t " + DatatypeConverter.printBase64Binary(encoding));
        System.out.println("HEX:\t " + bytesToHex(encoding));

        // Decode Base64
        byte[] ciphertext = DatatypeConverter.parseBase64Binary(DatatypeConverter.printBase64Binary(encoding));

        // Decrypt
        cipher.init(Cipher.DECRYPT_MODE, keySpec, new javax.crypto.spec.IvParameterSpec(IV.getBytes()));
        byte[] message = cipher.doFinal(ciphertext);

        System.out.println("-- Decrypted blowfish -----------");
        System.out.println("HEX:\t " + bytesToHex(message));
        System.out.println("PLAIN:\t " + new String(message));



    }
}