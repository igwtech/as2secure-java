package com.as2secure;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.security.PrivateKey;
import java.security.cert.CertStore;
import java.security.cert.Certificate;
import java.security.cert.CollectionCertStoreParameters;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Properties;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.internet.MimePart;
import org.bouncycastle.asn1.cms.AttributeTable;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.cms.jcajce.ZlibCompressor;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMECompressedGenerator;
import org.bouncycastle.mail.smime.SMIMESignedGenerator;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.util.Store;

public class AS2CommandSign
        extends AS2Secure {

    public boolean action(String[] args) {
        try {
            String[] arg_in = (String[]) null;
            String[] arg_out = (String[]) null;
            String[] arg_pkcs12 = (String[]) null;
            String[] arg_password = (String[]) null;
            String[] arg_nopassword = (String[]) null;
            boolean arg_compress = false;

            String[] arg_algo = (String[]) null;

            String password = "";

            try {
                arg_in = getArgument(args, "-in");
                arg_out = getArgument(args, "-out", 1, false);
                arg_pkcs12 = getArgument(args, "-pkcs12");
                arg_password = getArgument(args, "-password", 1, false);
                arg_nopassword = getArgument(args, "-nopassword", 1, false);
                arg_compress = hasArgument(args, "-compress");

                arg_algo = getArgument(args, "-algo", 1, false);

                if (arg_nopassword.length == 0) {
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
            certificateHelper.loadFromPKCS12(new File(arg_pkcs12[0]), password);

            PrivateKey privKey = certificateHelper.getPrivateKey();
            Certificate[] chain = certificateHelper.getCertificateChain();

            String algo = "sha1";
            if (arg_algo.length == 1) {
                algo = arg_algo[0];
            }

            MimeBodyPart bodyPart = null;
            bodyPart = SMIMEUtil.toMimeBodyPart(Utils.loadFile(arg_in[0]).getBytes());

            MimeMultipart signedData = null;

            if (arg_compress) {
                SMIMECompressedGenerator localSMIMECompressedGenerator = new SMIMECompressedGenerator();

                Properties localProperties = System.getProperties();
                Session localSession = Session.getDefaultInstance(localProperties, null);

                MimeBodyPart localMimeBodyPart = localSMIMECompressedGenerator.generate(bodyPart, new ZlibCompressor());

                MimeMessage localMimeMessage = new MimeMessage(localSession);
                localMimeMessage.setContent(localMimeBodyPart.getContent(), localMimeBodyPart.getContentType());
                localMimeMessage.saveChanges();

                signedData = sign(localMimeMessage, chain, privKey, algo);
            } else {

                signedData = sign(bodyPart, chain, privKey, algo);
            }

            if (arg_out.length == 1) {
                FileOutputStream output = new FileOutputStream(arg_out[0]);
                output.write("MIME-Version: 1.0\n".getBytes());
                output.write(("Content-Type: " + signedData.getContentType() + "\n\n").getBytes());
                signedData.writeTo(output);
            } else {
                System.out.print("MIME-Version: 1.0\n");
                System.out.print("Content-Type: " + signedData.getContentType() + "\n\n");
                signedData.writeTo(System.out);
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
        System.err.println("Standard commands\n -in <file>           : input file\n -out <file>          : output file compressed (optional)\n                         if not specified, standard output used\n -noout               : no output content at all\n\n -pkcs12 <file>       : path to the PKCS12 certificate container\n                          must contain private key / certificate / CA chain\n -password <password> : Password to open PKCS12\n -nopassword          : If the PKCS12 isn't securised\n\n -compress            : Zlib compress message before signing it\n -encoding <code>     : Transport encoding to use  (base64 | binary)\n                          if not specified, binary is used according to RFC\n -algo <algo>         : Algo to use for signing (sha1 | md5)\n                          if not specified, sha1 is used (the most common)");
    }

    protected MimeMultipart sign(MimePart body, Certificate[] chain, PrivateKey privKey) throws Exception {
        return sign(body, chain, privKey, "sha1");
    }

    protected MimeMultipart sign(MimePart body, Certificate[] chain, PrivateKey privKey, String digest) throws Exception {
        X509Certificate x509Cert = (X509Certificate) chain[0];
        SMIMESignedGenerator generator = new SMIMESignedGenerator();
        
        if (digest.equalsIgnoreCase("sha1")) {
            generator.addSignerInfoGenerator (new JcaSimpleSignerInfoGeneratorBuilder ().setProvider (BouncyCastleProvider.PROVIDER_NAME)
//                                                                            .setSignedAttributeGenerator (new AttributeTable (aSignedAttrs))
                                                                            .build (SMIMESignedGenerator.DIGEST_SHA1,
                                                                                    privKey,
                                                                                    x509Cert));
        } else if(digest.equalsIgnoreCase("sha2")) {
            //generator.addSigners(sis,SMIMESignedGenerator.DIGEST_SHA256);
            generator.addSignerInfoGenerator (new JcaSimpleSignerInfoGeneratorBuilder ().setProvider (BouncyCastleProvider.PROVIDER_NAME)
//                                                                            .setSignedAttributeGenerator (new AttributeTable (aSignedAttrs))
                                                                            .build (SMIMESignedGenerator.DIGEST_SHA256,
                                                                                    privKey,
                                                                                    x509Cert));
        }else if (digest.equalsIgnoreCase("md5")) {
            generator.addSignerInfoGenerator (new JcaSimpleSignerInfoGeneratorBuilder ().setProvider (BouncyCastleProvider.PROVIDER_NAME)
//                                                                            .setSignedAttributeGenerator (new AttributeTable (aSignedAttrs))
                                                                            .build (SMIMESignedGenerator.DIGEST_MD5,
                                                                                    privKey,
                                                                                    x509Cert));
        } else {

            throw new Exception("Signing digest " + digest + " not supported.");
        }

        Certificate[] chain_short = new Certificate[1];
        chain_short[0] = chain[0];

        ArrayList<Certificate> certList = new ArrayList<Certificate>(Arrays.asList(chain_short));
        CertStore certStore = CertStore.getInstance("Collection", new CollectionCertStoreParameters(certList), "BC");
        generator.addCertificates((Store)certStore);

        MimeMultipart signedPart = null;
        if (body instanceof MimeBodyPart) {
            signedPart = generator.generate((MimeBodyPart) body);
        } else if (body instanceof MimeMessage) {
            signedPart = generator.generate((MimeMessage) body);
        } else {
            throw new Exception("Unexpected message type.");
        }

        return signedPart;
    }
}
