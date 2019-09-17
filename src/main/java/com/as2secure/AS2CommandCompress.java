package com.as2secure;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import javax.mail.internet.MimeBodyPart;
import org.bouncycastle.cms.jcajce.ZlibCompressor;
import org.bouncycastle.mail.smime.SMIMECompressedGenerator;

public class AS2CommandCompress
        extends AS2Secure {

    public boolean action(String[] args) {
        try {
            String[] arg_in = (String[]) null;
            String[] arg_out = (String[]) null;
            String[] arg_encoding = (String[]) null;

            try {
                arg_in = getArgument(args, "-in");
                arg_out = getArgument(args, "-out", 1, false);
                arg_encoding = getArgument(args, "-encoding", 1, false);
            } catch (Exception e) {
                usage("error: " + e.getMessage());
                return false;
            }

            String transfertEncoding = "binary";
            if (arg_encoding.length == 1 && arg_encoding[0].equals("base64")) {
                transfertEncoding = arg_encoding[0];
            }

            SMIMECompressedGenerator compressor = new SMIMECompressedGenerator();

            MimeBodyPart inputMessage = new MimeBodyPart(new FileInputStream(arg_in[0]));
            MimeBodyPart middleMessage = compressor.generate(inputMessage, new ZlibCompressor());
            middleMessage.setHeader("Content-Transfer-Encoding", transfertEncoding);

            if (arg_out.length == 1) {
                FileOutputStream fileOutput = new FileOutputStream(arg_out[0]);
                middleMessage.writeTo(fileOutput);
            } else {
                middleMessage.writeTo(System.out);
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
        System.err.println("Standard commands\n -in <file>       : input file\n -out <file>      : output file compressed (optional)\n                      if not specified, standard output used\n -encoding <code> : Transport encoding to use  (base64 | binary)\n                      if not specified, binary is used according to RFC");
    }
}
