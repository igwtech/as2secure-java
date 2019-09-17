package com.as2secure;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.GeneralSecurityException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import javax.mail.MessagingException;
import javax.mail.internet.ContentType;
import javax.mail.internet.MimeBodyPart;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.cms.RecipientId;
import org.bouncycastle.cms.RecipientInformation;
import org.bouncycastle.cms.RecipientInformationStore;
import org.bouncycastle.cms.jcajce.JceKeyTransEnvelopedRecipient;
import org.bouncycastle.cms.jcajce.JceKeyTransRecipientId;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMEEnveloped;
import org.bouncycastle.mail.smime.SMIMEException;
import org.bouncycastle.mail.smime.SMIMEUtil;

public class AS2CommandDecrypt
        extends AS2Secure {

    public boolean action(String[] args) {
        try {
            String[] arg_in = (String[]) null;
            String[] arg_out = (String[]) null;
            String[] arg_pkcs12 = (String[]) null;
            String[] arg_password = (String[]) null;
            String[] arg_nopassword = (String[]) null;

            String password = "";

            try {
                arg_in = getArgument(args, "-in");
                arg_out = getArgument(args, "-out", 1, false);
                arg_pkcs12 = getArgument(args, "-pkcs12", 1, false);
                arg_password = getArgument(args, "-password", 1, false);
                arg_nopassword = getArgument(args, "-nopassword", 1, false);

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
            if (arg_pkcs12.length == 1) {
                certificateHelper.loadFromPKCS12(new File(arg_pkcs12[0]), password);
            }

            MimeBodyPart encryptedBodyPart = SMIMEUtil.toMimeBodyPart(new FileInputStream(arg_in[0]));

            MimeBodyPart decryptedBodyPart = decrypt(encryptedBodyPart, certificateHelper.getCertificate(), certificateHelper.getPrivateKey());

            if (arg_out.length == 1) {
                FileOutputStream output = new FileOutputStream(arg_out[0]);
                decryptedBodyPart.writeTo(output);

                output.close();
            } else {
                decryptedBodyPart.writeTo(System.out);
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
        System.err.println("Standard commands\n -in <file>           : input file\n -out <file>          : output file compressed (optional)\n                          if not specified, standard output used\n\n -pkcs12 <file>       : path to the PKCS12 certificate container\n                          must contain private key / certificate / CA chain\n -password <password> : Password to open PKCS12\n -nopassword          : If the PKCS12 isn't securised");
    }

    public boolean isEncrypted(MimeBodyPart part) throws MessagingException {
        ContentType contentType = new ContentType(part.getContentType());
        String baseType = contentType.getBaseType().toLowerCase();
        if (baseType.equalsIgnoreCase("application/pkcs7-mime")) {
            String smimeType = contentType.getParameter("smime-type");
            return (smimeType != null && smimeType.equalsIgnoreCase("enveloped-data"));
        }
        return false;
    }

    public MimeBodyPart decrypt(MimeBodyPart part, X509Certificate x509Cert, Key key) throws GeneralSecurityException, MessagingException, CMSException, IOException, SMIMEException {
        SMIMEEnveloped enveloped = new SMIMEEnveloped(part);

        RecipientId recId = new JceKeyTransRecipientId(x509Cert);

//        recId.setSerialNumber(x509Cert.getSerialNumber());
//        recId.setIssuer();

        RecipientInformationStore recipients = enveloped.getRecipientInfos();
        RecipientInformation recipient = recipients.get(recId);

        if (recipient != null) {

            return SMIMEUtil.toMimeBodyPart(recipient.getContent(new JceKeyTransEnvelopedRecipient((PrivateKey) key).setProvider (BouncyCastleProvider.PROVIDER_NAME)));
        }

        return null;
    }
}
