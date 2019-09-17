package com.as2secure;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import java.util.Properties;
import javax.mail.MessagingException;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMECompressed;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultDigestAlgorithmIdentifierFinder;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

public class AS2CommandVerify
        extends AS2Secure {

    public boolean action(String[] args) {
        try {
            String[] arg_in = (String[]) null;
            String[] arg_out = (String[]) null;
            boolean arg_noout = false;
            String[] arg_pkcs12 = (String[]) null;
            String[] arg_password = (String[]) null;
            String[] arg_nopassword = (String[]) null;
            String[] arg_cert = (String[]) null;

            try {
                arg_in = getArgument(args, "-in");
                arg_out = getArgument(args, "-out", 1, false);
                arg_noout = hasArgument(args, "-noout");
                arg_pkcs12 = getArgument(args, "-pkcs12", 1, false);
                arg_password = getArgument(args, "-password", 1, false);
                arg_nopassword = getArgument(args, "-nopassword", 1, false);
                arg_cert = getArgument(args, "-cert", 1, false);
            } catch (Exception e) {
                usage("error: " + e.getMessage());
                return false;
            }

            String password = "";
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

            CertificateHelper certificateHelper = new CertificateHelper();
            Properties localProperties = System.getProperties();
            Session localSession = Session.getDefaultInstance(localProperties, null);

            if (arg_pkcs12.length == 1) {
                certificateHelper.loadFromPKCS12(new File(arg_pkcs12[0]), password);
            } else if (arg_cert.length == 1) {
                certificateHelper.loadFromPEM(new File(arg_cert[0]));
            }

            FileInputStream inputStream = new FileInputStream(arg_in[0]);
            MimeMessage message = new MimeMessage(localSession, inputStream);

            MimeBodyPart verifiedMimePart = null;
            try {
                verifiedMimePart = verify(message, certificateHelper.getCertificate());
                System.err.println("verification succeeded");
            } catch (Exception e) {
                System.err.println("verification failed");
                System.err.println("error: " + e.getMessage());
                return false;
            }

            if (verifiedMimePart.getHeader("Content-Type")[0].indexOf("compressed-data") > 0) {
                SMIMECompressed localSMIMECompressed = new SMIMECompressed(verifiedMimePart);
                verifiedMimePart = SMIMEUtil.toMimeBodyPart(localSMIMECompressed.getContent(new ZlibExpanderProvider()));
            }

            if (!arg_noout) {
                if (arg_out.length == 1) {
                    FileOutputStream fileOutput = new FileOutputStream(arg_out[0]);
                    verifiedMimePart.writeTo(fileOutput);
                } else {

                    verifiedMimePart.writeTo(System.out);
                }

            }
        } catch (Exception e) {
            System.err.println(e.getMessage());
            return false;
        }

        return true;
    }

    protected static void usage(String message) {
        if (!message.equals("")) {
            System.err.println(String.valueOf(message) + "\n");
        }
        System.err.println("Standard commands\n -in <file>           : input file\n -out <file>          : output file compressed (optional)\n                         if not specified, standard output used\n -noout               : no output content at all\n -pkcs12 <file>       : path to the PKCS12 certificate container\n                          must contain private key / certificate / CA chain\n -password <password> : Password to open PKCS12\n -nopassword          : if the PKCS12 isn't securised -cert <file>         : path to the certificate (PEM format)");
    }

    protected MimeBodyPart verify(MimeMessage part, X509Certificate x509Cert) throws MessagingException, IOException, CMSException, GeneralSecurityException, OperatorCreationException {
        if (part.isMimeType("multipart/signed")) {
            MimeMultipart signedMultiPart = (MimeMultipart) part.getContent();

            SMIMESigned signed = null;
            signed = new SMIMESigned(signedMultiPart, "binary");
            SignerInformationVerifier siv = new JcaSimpleSignerInfoVerifierBuilder().setProvider(BouncyCastleProvider.PROVIDER_NAME)
                    .build(x509Cert.getPublicKey());
            SignerInformationStore signerStore = signed.getSignerInfos();
            Iterator<?> iterator = signerStore.getSigners().iterator();
            while (iterator.hasNext()) {
                SignerInformation signerInfo = (SignerInformation) iterator.next();
                if (!signerInfo.verify(siv)) {
                    throw new SignatureException("verification failed");
                }
            }
            return signed.getContent();
        }
        throw new GeneralSecurityException("Message isn't signed");
    }
}
