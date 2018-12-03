/*
 * Based on https://raw.githubusercontent.com/usefulfor/usefulfor/master/security/JBoss.java
 *
 * JBoss.java - Blowfish encryption/decryption tool with JBoss default password
 *    Daniel Martin Gomez <daniel@ngssoftware.com> - 03/Sep/2009
 *
 * This file may be used under the terms of the GNU General Public License
 * version 2.0 as published by the Free Software Foundation:
 *   http://www.gnu.org/licenses/gpl-2.0.html
 */
import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;

import java.math.BigInteger;
import javax.xml.bind.DatatypeConverter;

public class Blowfish
{
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

    public static void main(String[] args) throws Exception
    {
        System.out.println(args[0]);
        if ( ( args.length != 2 ) || !( args[0].equals("-e") | args[0].equals("-d") ) )
        {
            System.out.println( "Usage:\n\tjava JBlowfish <-e|-d> <encrypted_password>" );
            return;
        }

        String mode = args[0];

        // Configuration
        byte[] key	= "secret".getBytes();
        String IV  	= "12345678";


        System.out.println("-- Settings -----------");
        System.out.println("KEY:\t " + bytesToHex(key));
        System.out.println("IV:\t " + bytesToHex(IV.getBytes()));

        // Create new Blowfish cipher
        SecretKeySpec keySpec = new SecretKeySpec(key, "Blowfish");
        Cipher cipher = Cipher.getInstance("Blowfish/CBC/PKCS5Padding");
        String out = null;

        if ( mode.equals("-e") )
        {
            String secret = args[1];
            cipher.init(Cipher.ENCRYPT_MODE, keySpec, new javax.crypto.spec.IvParameterSpec(IV.getBytes()));
            byte[] encoding = cipher.doFinal(secret.getBytes());

            System.out.println("-- Encrypted -----------");
            System.out.println("Base64:\t " + DatatypeConverter.printBase64Binary(encoding));
            System.out.println("HEX:\t " + bytesToHex(encoding));
        }
        else
        {
            // Decode Base64
            byte[] ciphertext = DatatypeConverter.parseBase64Binary(args[1]);

            // Decrypt
            cipher.init(Cipher.DECRYPT_MODE, keySpec, new javax.crypto.spec.IvParameterSpec(IV.getBytes()));
            byte[] message = cipher.doFinal(ciphertext);

            System.out.println("-- Decrypted -----------");
            System.out.println("HEX:\t " + bytesToHex(message));
            System.out.println("PLAIN:\t " + new String(message));

        }
    }
}