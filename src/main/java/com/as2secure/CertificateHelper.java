package com.as2secure;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileReader;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Enumeration;
import java.util.Vector;
import javax.security.cert.CertificateParsingException;
import org.bouncycastle.jce.provider.X509CertificateObject;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.PEMWriter;

public class CertificateHelper {

    KeyStore ks = null;
    char[] password = null;

    PrivateKey privateKey = null;
    PublicKey publicKey = null;
    X509Certificate cert = null;
    Certificate[] chain = null;

    public void loadFromPKCS12(File file, String pass) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        loadFromPKCS12(file, pass, "");
    }

    public void loadFromPKCS12(File file, String pass, String alias) throws IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException {
        FileInputStream inputStream = new FileInputStream(file);
        this.password = pass.toCharArray();

        this.ks = KeyStore.getInstance("PKCS12");
        try {
            this.ks.load(inputStream, this.password);
        } catch (IOException e) {
            throw new KeyStoreException("Password seems to be wrong.");
        }

        Enumeration<String> en = this.ks.aliases();
        Vector vectaliases = new Vector();

        if (alias.equals("")) {
            while (en.hasMoreElements()) {
                vectaliases.add(en.nextElement());
            }
            String[] aliases = (String[]) vectaliases.toArray(new String[0]);
            for (int i = 0; i < aliases.length; i++) {
                if (this.ks.isKeyEntry(aliases[i])) {
                    alias = aliases[i];

                    break;
                }
            }
        }
        this.privateKey = (PrivateKey) this.ks.getKey(alias, this.password);
        this.publicKey = this.ks.getCertificate(alias).getPublicKey();
        this.cert = (X509Certificate) this.ks.getCertificate(alias);
        this.chain = this.ks.getCertificateChain(alias);
    }

    public void loadFromPEM(File file) throws IOException, CertificateParsingException {
        PEMParser reader = new PEMParser(new FileReader(file));
        Object obj = null;

        Vector<Certificate> listCert = new Vector<Certificate>();

        do {
            obj = reader.readObject();
            if (!(obj instanceof X509CertificateObject)) {
                continue;
            }
            listCert.add((Certificate) obj);

        } while (obj != null);

        if (listCert.size() >= 1) {
            this.chain = new Certificate[listCert.size()];
            listCert.copyInto(this.chain);
            this.cert = (X509Certificate) this.chain[0];
        } else {

            throw new CertificateParsingException("invalid DER-encoded certificate data");
        }
    }

    public void setCertificate(File file) throws IOException, CertificateParsingException {
        this.cert = getPEMCertificate(file);
    }

    public KeyStore getKeyStore() {
        return this.ks;
    }

    public PrivateKey getPrivateKey() {
        return this.privateKey;
    }

    public PublicKey getPublicKey() {
        return this.publicKey;
    }

    public X509Certificate getCertificate() {
        return this.cert;
    }

    public Certificate[] getCertificateChain() {
        return this.chain;
    }

    public X509Certificate getCertificateRoot() throws CertificateException {
        for (int i = 0; i < this.chain.length; i++) {
            Principal subject = ((X509Certificate) this.chain[i]).getSubjectDN();
            Principal issuer = ((X509Certificate) this.chain[i]).getIssuerDN();
            if (subject.equals(issuer)) {
                return (X509Certificate) this.chain[i];
            }
        }
        throw new CertificateException("Root certificate not found");
    }

    public static String getPrivateKeyAsEncodedString(PrivateKey priv) throws Exception {
        return getObjectAsEncodedString(priv);
    }

    public static String getPublicKeyAsEncodedString(PublicKey pub) throws Exception {
        return getObjectAsEncodedString(pub);
    }

    public static String getCertificateAsEncodedString(Certificate cert) throws Exception {
        return getObjectAsEncodedString(cert);
    }

    protected static String getObjectAsEncodedString(Object obj) throws Exception {
        ByteArrayOutputStream bOut = new ByteArrayOutputStream();
        PEMWriter pemWrt = new PEMWriter(new OutputStreamWriter(bOut));
        pemWrt.writeObject(obj);
        pemWrt.close();

        return Utils.toString(bOut.toByteArray());
    }

    public static X509Certificate getPEMCertificate(File file) throws CertificateParsingException, IOException {
        PEMParser reader = new PEMParser(new FileReader(file));
        Object obj = reader.readObject();

        if (obj instanceof X509CertificateObject) {
            return (X509CertificateObject) obj;
        }

        throw new CertificateParsingException("invalid DER-encoded certificate data");
    }
}
