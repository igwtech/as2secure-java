package com.as2secure;

import java.io.File;
import java.util.Enumeration;
import javax.activation.FileDataSource;
import javax.mail.MessagingException;
import javax.mail.internet.MimeMultipart;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1Set;
import org.bouncycastle.asn1.DERBMPString;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.DERBoolean;
import org.bouncycastle.asn1.ASN1Encodable;
import org.bouncycastle.asn1.DEREnumerated;
import org.bouncycastle.asn1.DERExternal;
import org.bouncycastle.asn1.DERGeneralizedTime;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.DERInteger;
import org.bouncycastle.asn1.DERNull;
import org.bouncycastle.asn1.ASN1Object;
import org.bouncycastle.asn1.DERObjectIdentifier;
import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.DERT61String;
import org.bouncycastle.asn1.DERTaggedObject;
import org.bouncycastle.asn1.DERUTCTime;
import org.bouncycastle.asn1.DERUTF8String;
//import org.bouncycastle.asn1.DERUnknownTag;
import org.bouncycastle.asn1.DERVisibleString;
import org.bouncycastle.cms.CMSException;
import org.bouncycastle.mail.smime.SMIMESigned;
import org.bouncycastle.util.encoders.Hex;

public class ASN1Helper {

    public static final String EMAIL_ADDRESS = "1.2.840.113549.1.9.1";
    public static final String MESSAGE_DIGEST = "1.2.840.113549.1.9.4";
    public static final String SIGNING_TIME = "1.2.840.113549.1.9.5";
    public static final String COMMON_NAME = "2.5.4.3";
    public static final String COUNTRY_NAME = "2.5.4.6";
    public static final String LOCALITY_NAME = "2.5.4.7";
    public static final String STATE_OR_PROVINCE_NAME = "2.5.4.8";
    public static final String ORGANIZATION_NAME = "2.5.4.10";
    public static final String ORGANIZATIONAL_UNIT_NAME = "2.5.4.11";
    protected boolean found;
    protected ASN1Object asn1;

    public ASN1Helper(ASN1Object asn1) {
        this.found = false;
        this.asn1 = null;

        this.asn1 = asn1;
    }

    public ASN1Helper(MimeMultipart mimeMultiPart) throws MessagingException, CMSException {
        this.found = false;
        this.asn1 = null;
        SMIMESigned signed = new SMIMESigned(mimeMultiPart);
        this.asn1 = signed.toASN1Structure().toASN1Primitive();
    }

    public ASN1Helper(File file) throws MessagingException, CMSException {
        this.found = false;
        this.asn1 = null;
        MimeMultipart multiPart = new MimeMultipart(new FileDataSource(file));
        SMIMESigned signed = new SMIMESigned(multiPart);
        this.asn1 = signed.toASN1Structure().toASN1Primitive();
    }

    public Object findByOID(String OID) {
        return findByOID(OID, false);
    }

    public Object findByOID(String OID, boolean asString) {
        this.found = false;
        Object obj = findByOID(this.asn1, OID);
        if (obj instanceof ASN1Set) {
            obj = ((ASN1Set) obj).getObjectAt(0);
        }
        if (asString) {
            return getValue(obj);
        }
        return obj;
    }

    public String getValue(Object obj) {
        return getReadable(obj);
    }

    protected Object findByOID(ASN1Object paramDERObject, String OID) {
        Object findByOIDObject = null;

        if (paramDERObject instanceof ASN1Sequence) {

            Object localObject1 = ((ASN1Sequence) paramDERObject).getObjects();

            while (((Enumeration) localObject1).hasMoreElements()) {
                Object localObject2 = ((Enumeration) localObject1).nextElement();
                if (localObject2 != null && !localObject2.equals(new DERNull())) {
                    if (localObject2 instanceof DERObjectIdentifier) {

                        String localOID = ((DERObjectIdentifier) localObject2).getId();
                        if (localOID.equals(OID)) {

                            this.found = true;
                            return ((Enumeration) localObject1).nextElement();
                        }

                        findByOIDObject = findByOID((ASN1Object) localObject2, OID);

                    } else if (localObject2 instanceof ASN1Object) {

                        findByOIDObject = findByOID((ASN1Object) localObject2, OID);
                    } else {

                        findByOIDObject = findByOID(((ASN1Encodable) localObject2).toASN1Primitive(), OID);
                    }
                }

                if (this.found) {
                    return findByOIDObject;
                }
            }

        } else if (paramDERObject instanceof DERTaggedObject) {

            Object localObject1 = (DERTaggedObject) paramDERObject;
            if (!((DERTaggedObject) localObject1).isEmpty()) {
                findByOIDObject = findByOID(((DERTaggedObject) localObject1).getObject(), OID);
            }
        } else if (paramDERObject instanceof org.bouncycastle.asn1.BERSet) {

            Object localObject1 = ((ASN1Set) paramDERObject).getObjects();
            while (((Enumeration) localObject1).hasMoreElements()) {
                Object localObject2 = ((Enumeration) localObject1).nextElement();
                if (localObject2 != null) {
                    if (localObject2 instanceof ASN1Object) {

                        findByOIDObject = findByOID((ASN1Object) localObject2, OID);
                    } else {

                        findByOIDObject = findByOID(((ASN1Encodable) localObject2).toASN1Primitive(), OID);
                    }
                }

                if (this.found) {
                    return findByOIDObject;
                }
            }

        } else if (paramDERObject instanceof org.bouncycastle.asn1.DERSet) {

            Object localObject1 = ((ASN1Set) paramDERObject).getObjects();
            while (((Enumeration) localObject1).hasMoreElements()) {
                Object localObject2 = ((Enumeration) localObject1).nextElement();
                if (localObject2 != null) {
                    if (localObject2 instanceof ASN1Object) {
                        findByOIDObject = findByOID((ASN1Object) localObject2, OID);
                    } else {
                        findByOIDObject = findByOID(((ASN1Encodable) localObject2).toASN1Primitive(), OID);
                    }
                }

                if (this.found) {
                    return findByOIDObject;
                }
            }

        } else if (paramDERObject instanceof DERExternal) {

            Object localObject1 = (DERExternal) paramDERObject;
            if (((DERExternal) localObject1).getDataValueDescriptor() != null) {
                findByOIDObject = findByOID(((DERExternal) localObject1).getDataValueDescriptor(), OID);
            } else {
                findByOIDObject = findByOID(((DERExternal) localObject1).getExternalContent(), OID);
            }
        }
        return findByOIDObject;
    }

    protected String getReadable(Object paramDERObject) {
        Object localObject = null;

        if (paramDERObject instanceof DERObjectIdentifier) {
            return ((DERObjectIdentifier) paramDERObject).getId();
        }
        if (paramDERObject instanceof DERBoolean) {

            if (((DERBoolean) paramDERObject).isTrue()) {
                return "true";
            }
            return "false";
        }
        if (paramDERObject instanceof DERInteger) {
            return ((DERInteger) paramDERObject).getValue().toString();
        }
        if (paramDERObject instanceof org.bouncycastle.asn1.BERConstructedOctetString) {

            localObject = (ASN1OctetString) paramDERObject;
            return dumpBinaryDataAsString(((ASN1OctetString) localObject).getOctets());
        }
        if (paramDERObject instanceof org.bouncycastle.asn1.DEROctetString) {

            localObject = (ASN1OctetString) paramDERObject;
            return dumpBinaryDataAsString(((ASN1OctetString) localObject).getOctets());
        }
        if (paramDERObject instanceof DERBitString) {

            localObject = (DERBitString) paramDERObject;
            return dumpBinaryDataAsString(((DERBitString) localObject).getBytes());
        }
        if (paramDERObject instanceof DERIA5String) {
            return ((DERIA5String) paramDERObject).getString();
        }
        if (paramDERObject instanceof DERUTF8String) {
            return ((DERUTF8String) paramDERObject).getString();
        }
        if (paramDERObject instanceof DERPrintableString) {
            return ((DERPrintableString) paramDERObject).getString();
        }
        if (paramDERObject instanceof DERVisibleString) {
            return ((DERVisibleString) paramDERObject).getString();
        }
        if (paramDERObject instanceof DERBMPString) {
            return ((DERBMPString) paramDERObject).getString();
        }
        if (paramDERObject instanceof DERT61String) {
            return ((DERT61String) paramDERObject).getString();
        }
        if (paramDERObject instanceof DERUTCTime) {
            return ((DERUTCTime) paramDERObject).getTime();
        }
        if (paramDERObject instanceof DERGeneralizedTime) {
            return ((DERGeneralizedTime) paramDERObject).getTime();
        }
//        if (paramDERObject instanceof DERUnknownTag) {
//            return String.valueOf(Integer.toString(((DERUnknownTag) paramDERObject).getTag(), 16)) + " " + new String(Hex.encode(((DERUnknownTag) paramDERObject).getData()));
//        }
        if (!(paramDERObject instanceof org.bouncycastle.asn1.BERApplicationSpecific)) {

            if (!(paramDERObject instanceof org.bouncycastle.asn1.DERApplicationSpecific)) {

                if (paramDERObject instanceof DEREnumerated) {

                    localObject = (DEREnumerated) paramDERObject;
                    return ((DEREnumerated) localObject).getValue().toString();
                }
            }
        }
        return paramDERObject.toString();
    }

    protected String dumpBinaryDataAsString(byte[] binary) {
        return new String(Hex.encode(binary));
    }
}
