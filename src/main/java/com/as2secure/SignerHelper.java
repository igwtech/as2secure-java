 package com.as2secure;
 
 import java.security.PrivateKey;
 import java.security.cert.CertStore;
 import java.security.cert.X509Certificate;
 import javax.mail.internet.MimeBodyPart;
 import javax.mail.internet.MimeMultipart;
 import org.bouncycastle.asn1.ASN1EncodableVector;
 import org.bouncycastle.asn1.cms.AttributeTable;
 import org.bouncycastle.asn1.smime.SMIMECapabilitiesAttribute;
 import org.bouncycastle.asn1.smime.SMIMECapability;
 import org.bouncycastle.asn1.smime.SMIMECapabilityVector;
 import org.bouncycastle.asn1.smime.SMIMEEncryptionKeyPreferenceAttribute;
import org.bouncycastle.cms.jcajce.JcaSimpleSignerInfoGeneratorBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
 import org.bouncycastle.mail.smime.SMIMESignedGenerator;
 import org.bouncycastle.mail.smime.SMIMEUtil;
import org.bouncycastle.util.Store;

 
 public class SignerHelper
 {
   public static MimeMultipart sign(PrivateKey key, X509Certificate cert, CertStore certsAndCRLs, MimeBodyPart dataPart) throws Exception {
     ASN1EncodableVector signedAttrs = new ASN1EncodableVector();
     SMIMECapabilityVector caps = new SMIMECapabilityVector();
     
     caps.addCapability(SMIMECapability.aES256_CBC);
     caps.addCapability(SMIMECapability.dES_EDE3_CBC);
     caps.addCapability(SMIMECapability.rC2_CBC, 128);
     
     signedAttrs.add(new SMIMECapabilitiesAttribute(caps));
     signedAttrs.add(new SMIMEEncryptionKeyPreferenceAttribute(SMIMEUtil.createIssuerAndSerialNumberFor(cert)));
 
     
     SMIMESignedGenerator gen = new SMIMESignedGenerator();
     gen.addSignerInfoGenerator (new JcaSimpleSignerInfoGeneratorBuilder ().setProvider (BouncyCastleProvider.PROVIDER_NAME)
                                                                            .setSignedAttributeGenerator (new AttributeTable (signedAttrs))
                                                                            .build (SMIMESignedGenerator.DIGEST_SHA1,
                                                                                    key,
                                                                                    cert));
     gen.addCertificates((Store)certsAndCRLs);
     
     return gen.generate(dataPart);
   }
 }
