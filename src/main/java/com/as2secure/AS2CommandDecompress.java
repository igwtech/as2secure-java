package com.as2secure;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.util.Properties;
import javax.mail.Session;
import javax.mail.internet.MimeBodyPart;
import javax.mail.internet.MimeMessage;
import org.bouncycastle.cms.jcajce.ZlibExpanderProvider;
import org.bouncycastle.mail.smime.SMIMECompressed;
import org.bouncycastle.mail.smime.SMIMEUtil;

public class AS2CommandDecompress
        extends AS2Secure {

    public boolean action(String[] args) {
        try {
            String[] arg_in = (String[]) null;
            String[] arg_out = (String[]) null;

            try {
                arg_in = getArgument(args, "-in");
                arg_out = getArgument(args, "-out", 1, false);
            } catch (Exception e) {
                usage("error: " + e.getMessage());
                return false;
            }

            Properties localProperties = System.getProperties();
            Session localSession = Session.getDefaultInstance(localProperties, null);

            MimeMessage localMimeMessage = new MimeMessage(localSession, new FileInputStream(arg_in[0]));
            SMIMECompressed localSMIMECompressed = new SMIMECompressed(localMimeMessage);
            MimeBodyPart localMimeBodyPart = SMIMEUtil.toMimeBodyPart(localSMIMECompressed.getContent(new ZlibExpanderProvider()));

            if (arg_out.length == 1) {
                FileOutputStream fileOutput = new FileOutputStream(arg_out[0]);
                localMimeBodyPart.writeTo(fileOutput);
            } else {
                localMimeBodyPart.writeTo(System.out);
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
        System.err.println("Standard commands\n -in <file>  : input file\n -out <file> : output file compressed (optional)\n                 if not specified, standard output used");
    }
}
