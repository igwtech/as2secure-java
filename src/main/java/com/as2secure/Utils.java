package com.as2secure;

import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.StringWriter;
import java.security.NoSuchAlgorithmException;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.util.encoders.Hex;

public class Utils {

    public static String loadFile(String string) throws IOException {
        return loadFile(new File(string));
    }

    public static String loadFile(File file) throws IOException {
        BufferedInputStream in = new BufferedInputStream(new FileInputStream(file));
        StringWriter out = new StringWriter();
        int b;
        while ((b = in.read()) != -1) {
            out.write(b);
        }
        out.flush();
        out.close();
        in.close();
        return out.toString();
    }

    public static String toString(byte[] bytes) {
        return toString(bytes, bytes.length);
    }

    public static String toString(byte[] bytes, int length) {
        char[] chars = new char[length];

        for (int i = 0; i != chars.length; i++) {
            chars[i] = (char) (bytes[i] & 0xFF);
        }

        return new String(chars);
    }

    public static void copyStreams(InputStream input, OutputStream output) throws IOException {
        BufferedInputStream inStream = new BufferedInputStream(input);
        BufferedOutputStream outStream = new BufferedOutputStream(output);

        byte[] buffer = new byte[4096];
        int read = 0;

        while (read != -1) {
            read = inStream.read(buffer);
            if (read > 0) {
                outStream.write(buffer, 0, read);
            }
        }
        outStream.flush();
    }

    public static String convertAlgorithmNameToOID(String algorithm) throws IOException, NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NoSuchAlgorithmException("Algorithm is null");
        }
        if (algorithm.equalsIgnoreCase("3des")) {
            return PKCSObjectIdentifiers.des_EDE3_CBC.getId();
        }
        if (algorithm.equalsIgnoreCase("des")) {
            return "1.3.14.3.2.7";
        }
        if (algorithm.equalsIgnoreCase("rc2")) {
            return PKCSObjectIdentifiers.RC2_CBC.getId();
        }
        if (algorithm.equalsIgnoreCase("rc4")) {
            return "1.2.840.113549.3.4";
        }
        if (algorithm.equalsIgnoreCase("aes128")) {
            return CMSEnvelopedDataGenerator.AES128_CBC;
        }
        if (algorithm.equalsIgnoreCase("aes192")) {
            return CMSEnvelopedDataGenerator.AES192_CBC;
        }
        if (algorithm.equalsIgnoreCase("aes256")) {
            return CMSEnvelopedDataGenerator.AES256_CBC;
        }
        throw new NoSuchAlgorithmException("Unsupported algorithm: " + algorithm);
    }

    public static int getKeySizeFromAlgorithmName(String algorithm) throws NoSuchAlgorithmException {
        if (algorithm == null) {
            throw new NoSuchAlgorithmException("Algorithm is null");
        }
        if (algorithm.equalsIgnoreCase("3des")) {
            return 128;
        }
        if (algorithm.equalsIgnoreCase("des")) {
            return 56;
        }
        if (algorithm.equalsIgnoreCase("rc2")) {
            return 128;
        }
        if (algorithm.equalsIgnoreCase("rc4")) {
            return 128;
        }
        if (algorithm.equalsIgnoreCase("aes128")) {
            return 128;
        }
        if (algorithm.equalsIgnoreCase("aes192")) {
            return 128;
        }
        if (algorithm.equalsIgnoreCase("aes256")) {
            return 128;
        }
        throw new NoSuchAlgorithmException("Unsupported algorithm: " + algorithm);
    }

    public static byte[] hexToBin(String hex) {
        byte[] data = new byte[hex.length() / 2];

        for (int i = 0; i < hex.length(); i += 2) {

            String sub = hex.substring(i, i + 2);
            data[i / 2] = Hex.decode(sub)[0];
        }

        return data;
    }
}
