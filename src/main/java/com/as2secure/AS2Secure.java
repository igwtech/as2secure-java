package com.as2secure;

import java.security.Security;
import java.util.Arrays;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class AS2Secure {

    public static void main(String[] args) throws Exception {
        AS2Secure as2Command = null;

        try {
            Security.addProvider(new BouncyCastleProvider());

            boolean commandReturn = false;

            if (args.length >= 1) {
                String command = args[0];

                if (command.equals("compose")) {
                    as2Command = new AS2CommandCompose();
                } else if (command.equals("extract")) {
                    as2Command = new AS2CommandExtract();
                } else if (command.equals("sign")) {
                    as2Command = new AS2CommandSign();
                } else if (command.equals("verify")) {
                    as2Command = new AS2CommandVerify();
                } else if (command.equals("encrypt")) {
                    as2Command = new AS2CommandEncrypt();
                } else if (command.equals("decrypt")) {
                    as2Command = new AS2CommandDecrypt();
                } else if (command.equals("compress")) {
                    as2Command = new AS2CommandCompress();
                } else if (command.equals("decompress")) {
                    as2Command = new AS2CommandDecompress();
                } else if (command.equals("checksum")) {
                    as2Command = new AS2CommandChecksum();
                } else {

                    usage("Error: '" + command + "' is an invalid command.");
                }

                if (as2Command != null) {
                    commandReturn = as2Command.action(arrayShift(args));
                }
            } else {

                usage("");
            }

            if (!commandReturn) {
                System.exit(1);
            }
        } catch (Exception e) {

            usage(e.getMessage());

            System.exit(1);
        }

        System.exit(0);
    }

    protected boolean action(String[] args) {
        System.err.println("Must be overridden into module.");
        return false;
    }

    protected static void usage(String message) {
        if (!message.equals("")) {
            System.err.println(String.valueOf(message) + "\n");
        }
        System.err.println("Usage: <command> <options>\n\nStandard commands\n compose    : TODO\n extract    : TODO\n sign       : \n verify     : \n encrypt    : \n decrypt    : \n compress   : \n decompress : ");
    }

    protected static String[] arrayShift(String[] args) {
        return (String[]) Arrays.copyOfRange(args, 1, args.length);
    }

    protected static String[] getArgument(String[] args, String argument) throws Exception {
        return getArgument(args, argument, 1, true);
    }

    protected static String[] getArgument(String[] args, String argument, int count) throws Exception {
        return getArgument(args, argument, count, true);
    }

    protected static String[] getArgument(String[] args, String argument, int count, boolean mandatory) throws Exception {
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals(argument)) {
                int end = count + i;
                if (end > args.length && mandatory) {
                    throw new Exception("Not enought arguments found");
                }
                return (String[]) Arrays.copyOfRange(args, i + 1, end + 1);
            }
        }

        if (mandatory) {
            throw new Exception("Argument not found : \"" + argument + "\"");
        }
        return new String[0];
    }

    protected static boolean hasArgument(String[] args, String argument) {
        for (int i = 0; i < args.length; i++) {
            if (args[i].equals(argument)) {
                return true;
            }
        }

        return false;
    }
}
