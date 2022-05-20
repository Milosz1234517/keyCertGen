import sun.security.x509.*;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.net.InetAddress;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

public class Main {

    KeyStore ks;

    public static void main(String[] args) {

        try {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(1024, new SecureRandom());
            KeyPair keyPair = generator.generateKeyPair();
            FileOutputStream keyStoreOut = new FileOutputStream("pvc-key-store");
            KeyStore keyStore = KeyStore.getInstance(KeyStore.getDefaultType());
            keyStore.load(null, "".toCharArray());
            X509Certificate[] chain = {Main.generateCertificate("cn=localhost", keyPair, 365, "SHA256withRSA", new String[]{"127.0.0.1", "217.96.254.166"})};
            keyStore.setKeyEntry("sslCert", keyPair.getPrivate(), "".toCharArray(), chain);
            keyStore.store(keyStoreOut, "".toCharArray());

        } catch (CertificateException | NoSuchAlgorithmException | KeyStoreException | IOException e) {
            e.printStackTrace();
        }


    }

    public void loadKeystore(String name, String password){
        try {
            ks = KeyStore.getInstance("JCEKS");
            ks.load(new FileInputStream(name + ".jceks"), password.toCharArray());
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    public void createKeystore(String name, String password){
        try {
            KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
            char[] pwdArray = password.toCharArray();
            ks.load(null, pwdArray);

            FileOutputStream fos = new FileOutputStream(name + ".jceks");
            ks.store(fos, pwdArray);
        }catch (Exception e){
            e.printStackTrace();
        }
    }

    private static X509Certificate generateCertificate(String dn, KeyPair keyPair, int validity, String sigAlgName, String[] serverIP) {
        try {
            PrivateKey privateKey = keyPair.getPrivate();

            X509CertInfo info = new X509CertInfo();

            Date from = new Date();
            Date to = new Date(from.getTime() + validity * 1000L * 24L * 60L * 60L);

            CertificateValidity interval = new CertificateValidity(from, to);
            BigInteger serialNumber = new BigInteger(64, new SecureRandom());
            X500Name owner = new X500Name(dn);
            AlgorithmId sigAlgId = new AlgorithmId(AlgorithmId.md5WithRSAEncryption_oid);

            info.set(X509CertInfo.VALIDITY, interval);
            info.set(X509CertInfo.SERIAL_NUMBER, new CertificateSerialNumber(serialNumber));
            info.set(X509CertInfo.SUBJECT, owner);
            final String LOCAL_HOST = InetAddress.getLocalHost().getHostName();

            GeneralNames altNames = new GeneralNames();
            for (String ipAdd: serverIP) {
                altNames.add(new GeneralName(new IPAddressName(ipAdd)));
            }
            altNames.add(new GeneralName(new DNSName("localhost")));

            SubjectAlternativeNameExtension san = new SubjectAlternativeNameExtension(altNames);

            final CertificateExtensions certificateExtensions = new CertificateExtensions();

            String ax = san.getExtensionId().toString();
            certificateExtensions.set(ax, san);
            info.set(X509CertInfo.ISSUER, owner);
            info.set(X509CertInfo.KEY, new CertificateX509Key(keyPair.getPublic()));
            info.set(X509CertInfo.VERSION, new CertificateVersion(CertificateVersion.V3));
            info.set(X509CertInfo.ALGORITHM_ID, new CertificateAlgorithmId(sigAlgId));
            info.set(X509CertInfo.EXTENSIONS, certificateExtensions);

            // Sign the cert to identify the algorithm that's used.
            X509CertImpl certificate = new X509CertImpl(info);
            certificate.sign(privateKey, sigAlgName);

            // Update the algorith, and resign.
            sigAlgId = (AlgorithmId) certificate.get(X509CertImpl.SIG_ALG);
            info.set(CertificateAlgorithmId.NAME + "." + CertificateAlgorithmId.ALGORITHM, sigAlgId);
            certificate = new X509CertImpl(info);
            certificate.sign(privateKey, sigAlgName);

            return certificate;
        }catch (Exception e){
            e.printStackTrace();
            return null;
        }
    }

}
