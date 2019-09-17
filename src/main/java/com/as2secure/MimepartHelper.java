 package com.as2secure;
 
 import java.io.ByteArrayOutputStream;
 import java.io.File;
 import java.io.FileInputStream;
 import java.io.FileNotFoundException;
 import java.io.IOException;
 import java.util.Properties;
 import javax.mail.MessagingException;
 import javax.mail.Session;
 import javax.mail.internet.MimeMessage;
 import javax.mail.internet.MimeMultipart;
 import javax.mail.util.ByteArrayDataSource;
 

 public class MimepartHelper
 {
   public static MimeMultipart getMultipartFromFile(File file) throws FileNotFoundException, MessagingException, IOException { return getMultipartFromFile(new FileInputStream(file)); }
 
 
   
   public static MimeMultipart getMultipartFromFile(String filename) throws MessagingException, IOException { return getMultipartFromFile(new FileInputStream(filename)); }
 
   
   public static MimeMultipart getMultipartFromFile(FileInputStream fileInputStream) throws MessagingException, IOException {
     Properties localProperties = System.getProperties();
     Session localSession = Session.getDefaultInstance(localProperties, null);
     
     MimeMessage message = new MimeMessage(localSession, fileInputStream);
     ByteArrayOutputStream mem = new ByteArrayOutputStream();
     message.writeTo(mem);
     mem.flush();
     mem.close();
     
     return new MimeMultipart(new ByteArrayDataSource(mem.toByteArray(), message.getContentType()));
   }
 }
