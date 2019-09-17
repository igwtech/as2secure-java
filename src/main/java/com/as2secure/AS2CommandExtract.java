package com.as2secure;

import java.io.ByteArrayOutputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.security.GeneralSecurityException;
import java.security.SignatureException;
import java.security.cert.X509Certificate;
import java.util.Iterator;
import javax.mail.BodyPart;
import javax.mail.MessagingException;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import javax.mail.internet.MimeMultipart;
import javax.mail.util.ByteArrayDataSource;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cms.DefaultCMSSignatureAlgorithmNameGenerator;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.cms.SignerInformationVerifier;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoVerifierBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.operator.ContentVerifier;
import org.bouncycastle.operator.ContentVerifierProvider;
import org.bouncycastle.operator.DefaultSignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.bc.BcDigestCalculatorProvider;

public class AS2CommandExtract
        extends AS2Secure {

    public boolean action(String[] args) {
        try {
            String[] arg_in = (String[]) null;
            String[] arg_out = (String[]) null;

            try {
                arg_in = getArgument(args, "-in");
                arg_out = getArgument(args, "-out");
            } catch (Exception e) {
                usage("error: " + e.getMessage());
                return false;
            }

            MimeBodyPart message = SMIMEUtil.toMimeBodyPart(Utils.loadFile(arg_in[0]).getBytes());

            if (message.isMimeType("multipart/*")) {
                ByteArrayOutputStream mem = new ByteArrayOutputStream();
                ((MimeMultipart) message.getContent()).writeTo(mem);
                mem.flush();
                mem.close();
                MimeMultipart multiPart = new MimeMultipart(new ByteArrayDataSource(mem.toByteArray(), ((MimeMultipart) message.getContent()).getContentType()));

                for (int i = 0; i < multiPart.getCount(); i++) {
                    ByteArrayOutputStream payloadOut = new ByteArrayOutputStream();
                    InputStream payloadIn = multiPart.getBodyPart(i).getInputStream();
                    Utils.copyStreams(payloadIn, payloadOut);
                    payloadOut.flush();
                    payloadOut.close();
                    byte[] data = payloadOut.toByteArray();

                    String filename = String.valueOf(arg_out[0]) + "_" + i;
                    System.out.println(logFile(multiPart.getBodyPart(i), filename));
                    FileOutputStream fileOutput = new FileOutputStream(filename);
                    fileOutput.write(data);
                }
            } else {

                String filename = String.valueOf(arg_out[0]) + "_0";
                System.out.println(logFile(message, filename));
                message.saveFile(filename);
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
        System.err.println("Standard commands\n -in <file>           : input file\n -out <file>          : output file compressed");
    }

    protected String logFile(BodyPart part, String filename) throws MessagingException {
        String contentType = part.getContentType();
        if (contentType.indexOf(";") > 0) {
            contentType = contentType.substring(0, contentType.indexOf(";"));
        }
        String originalFilename = part.getFileName();
        return String.valueOf(filename) + ";" + contentType + ";" + originalFilename;
    }

    protected MimeBodyPart extract(MimeMessage part, X509Certificate x509Cert) throws Exception {
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
        throw new GeneralSecurityException("Data isn't signed");
    }
}
