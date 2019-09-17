package com.as2secure;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.security.DigestInputStream;
import java.security.GeneralSecurityException;
import java.security.MessageDigest;
import java.util.Iterator;
import javax.activation.FileDataSource;
import javax.mail.Part;
import javax.mail.internet.MimeMultipart;
import org.bouncycastle.cms.SignerInformation;
import org.bouncycastle.cms.SignerInformationStore;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.util.encoders.Base64;

public class AS2CommandChecksum
        extends AS2Secure {

    public boolean action(String[] args) {
        try {
            String[] arg_in = (String[]) null;

            try {
                arg_in = getArgument(args, "-in");
            } catch (Exception e) {
                usage("error: " + e.getMessage());
                return false;
            }

            MimeMultipart multiPart = new MimeMultipart(new FileDataSource(arg_in[0]));
            System.out.println(calculateMIC(multiPart.getBodyPart(0), multiPart.getBodyPart(1)));
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
        System.err.println("Standard commands\n -in <file>  : input file");
    }

    public String getDigestAlgOIDFromSignature_new(Part part) throws Exception {
        SMIMESigned signed = new SMIMESigned(part);
        SignerInformationStore signerStore = signed.getSignerInfos();
        Iterator<?> iterator = signerStore.getSigners().iterator();
        if (iterator.hasNext()) {
            SignerInformation signerInfo = (SignerInformation) iterator.next();
            if (signerInfo.getDigestAlgOID().equals("1.3.14.3.2.26")) {
                return "sha1";
            }
            if (signerInfo.getDigestAlgOID().equals("1.2.840.113549.2.5")) {
                return "md5";
            }
        }
        throw new GeneralSecurityException("Unable to identify signature algorithm.");
    }

    public String getDigestAlgOIDFromSignature(Part part) throws Exception {
        SMIMESigned signed = new SMIMESigned(part);
        SignerInformationStore signerStore = signed.getSignerInfos();
        Iterator<?> iterator = signerStore.getSigners().iterator();
        if (iterator.hasNext()) {
            SignerInformation signerInfo = (SignerInformation) iterator.next();
            return signerInfo.getDigestAlgOID();
        }
        throw new GeneralSecurityException("Unable to identify signature algorithm.");
    }

    public String calculateMIC(Part content, Part signature) throws Exception {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        content.writeTo(bOut);
        bOut.flush();
        bOut.close();
        byte[] data = bOut.toByteArray();

        String digestAlgOID = getDigestAlgOIDFromSignature(signature);

        MessageDigest messageDigest = MessageDigest.getInstance(digestAlgOID, "BC");
        DigestInputStream digestInputStream = new DigestInputStream(new ByteArrayInputStream(data), messageDigest);
        byte[] buf = new byte[4096];
        do {
        } while (digestInputStream.read(buf) >= 0);
        byte[] mic = digestInputStream.getMessageDigest().digest();
        digestInputStream.close();
        String micString = new String(Base64.encode(mic));

        String digestAlgName = "";
        if (digestAlgOID.equals("1.3.14.3.2.26")) {
            digestAlgName = "sha1";
        } else if (digestAlgOID.equals("1.2.840.113549.2.5")) {
            digestAlgName = "md5";
        }
        return String.valueOf(micString) + ", " + digestAlgName;
    }
}
