package com.as2secure;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import javax.mail.internet.MimeBodyPart;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.cms.CMSEnvelopedData;
import org.bouncycastle.cms.CMSEnvelopedDataGenerator;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.CMSProcessableByteArray;
import org.bouncycastle.cms.jcajce.JceCMSContentEncryptorBuilder;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientInfoGenerator;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OutputEncryptor;

public class AS2CommandEncrypt
        extends AS2Secure {

    public boolean action(String[] args) {
        try {
            String[] arg_in = (String[]) null;
            String[] arg_out = (String[]) null;
            String[] arg_cert = (String[]) null;
            String[] arg_pkcs12 = (String[]) null;
            String[] arg_password = (String[]) null;
            String[] arg_nopassword = (String[]) null;
            String[] arg_cypher = (String[]) null;

            String password = "";

            try {
                arg_in = getArgument(args, "-in");
                arg_out = getArgument(args, "-out", 1, false);
                arg_cert = getArgument(args, "-cert", 1, false);
                arg_pkcs12 = getArgument(args, "-pkcs12", 1, false);
                arg_password = getArgument(args, "-password", 1, false);
                arg_nopassword = getArgument(args, "-nopassword", 1, false);
                arg_cypher = getArgument(args, "-cypher", 1, false);

                if (arg_pkcs12.length == 1
                        && arg_nopassword.length == 0) {
                    if (arg_password.length == 0) {

                        System.err.print("PKCS12 password : ");
                        BufferedReader br = new BufferedReader(new InputStreamReader(System.in));
                        password = br.readLine();
                        br.close();
                    } else {

                        password = arg_password[0];
                    }

                }
            } catch (Exception e) {
                usage("error: " + e.getMessage());
                return false;
            }

            CertificateHelper certificateHelper = new CertificateHelper();
            if (arg_pkcs12.length == 1) {
                certificateHelper.loadFromPKCS12(new File(arg_pkcs12[0]), password);
            } else {
                certificateHelper.loadFromPEM(new File(arg_cert[0]));
            }

            String cypher = "3des";
            if (arg_cypher.length == 1) {
                cypher = arg_cypher[0];
            }

            MimeBodyPart bodyPart = new MimeBodyPart();
            bodyPart.attachFile(arg_in[0]);

            byte[] rawData = Utils.loadFile(new File(arg_in[0])).getBytes();
            byte[] cryptedData = encrypt(rawData, certificateHelper.getCertificate(), cypher);

            byte[] headers = "Content-Type: application/pkcs7-mime; smime-type=enveloped-data; name=smime.p7m\nContent-Disposition: attachment; filename=\"smime.p7m\"\nContent-Transfer-Encoding: binary\n\n"
                    .getBytes();

            if (arg_out.length == 1) {
                FileOutputStream output = new FileOutputStream(arg_out[0]);
                output.write(headers);
                output.write(cryptedData);
                output.close();
            } else {
                System.out.print(headers);
                System.out.print(cryptedData);
            }

        } catch (Exception e) {
            System.err.println(e.getMessage());
            e.printStackTrace();
            return false;
        }

        return true;
    }

    protected static void usage(String message) {
        if (!message.equals("")) {
            System.err.println(String.valueOf(message) + "\n");
        }
        System.err.println("Standard commands\n -in <file>        : input file\n -out <file>       : output file compressed (optional)\n                      if not specified, standard output used\n\n -cert <file>      : path to the certificate (PEM format)\n -cypher <cypher>  : cypher to use (3des | des | rc2 | rc4 | aes128 | aes192 | aes256)\n                      if not specified, 3des is used");
    }

    protected byte[] encrypt(byte[] message, X509Certificate x509Cert, String algorithm) throws IOException, NoSuchAlgorithmException, NoSuchProviderException, CMSException, CertificateEncodingException {
        String encAlg = Utils.convertAlgorithmNameToOID(algorithm);
        int encSize = Utils.getKeySizeFromAlgorithmName(algorithm);
        CMSProcessableByteArray byteArray = new CMSProcessableByteArray(message);

        CMSEnvelopedDataGenerator dataGenerator = new CMSEnvelopedDataGenerator();
        dataGenerator.addRecipientInfoGenerator(new JceKeyTransRecipientInfoGenerator(x509Cert));
        final OutputEncryptor aEncryptor = new JceCMSContentEncryptorBuilder (new ASN1ObjectIdentifier(encAlg)).setProvider (BouncyCastleProvider.PROVIDER_NAME)
                                                                                  .build ();
        CMSEnvelopedData envelopedData = dataGenerator.generate( byteArray, aEncryptor );
        return envelopedData.getEncoded();
    }
}
