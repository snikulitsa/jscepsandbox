import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.jscep.client.Client;
import org.jscep.client.ClientException;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.EnrollmentResponse;
import org.jscep.client.verification.ConsoleCertificateVerifier;
import org.jscep.transaction.TransactionException;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.*;
import java.security.cert.*;
import java.security.cert.Certificate;
import java.util.Calendar;
import java.util.Collection;
import java.util.Date;

public class JscepSandbox {

    private final static String SCEP_DOGTAG = "http://localhost:32775/ca/cgi-bin/pkiclient.exe";

    public static void main(String[] args) {

        try {

            //SCEP CLIENT
            URL url = new URL(SCEP_DOGTAG);
            Client jscepClient = new Client(
                    url,
                    new DefaultCallbackHandler(new ConsoleCertificateVerifier())
            );
            System.out.println(
                    "STRONGEST ALGORITHM = "
                            + jscepClient.getCaCapabilities().getStrongestSignatureAlgorithm()
            );

//            //SELF-SIGNED
//            KeyPair registererKeyPair = generateKeys("RSA", 1024);
//            X500Principal issuer = new X500Principal("CN=self-signet, L=test, ST=test, C=RU");
//            BigInteger serial = BigInteger.ONE;
//            Calendar calendar = Calendar.getInstance();
//            calendar.add(Calendar.DATE, -1);
//            Date notBefore = calendar.getTime();
//            calendar.add(Calendar.DATE, +2);
//            Date notAfter = calendar.getTime();
//            X500Principal requester = new X500Principal("CN=self-signet, L=test, ST=test, C=RU");
//            JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
//                    issuer,
//                    serial,
//                    notBefore,
//                    notAfter,
//                    requester,
//                    registererKeyPair.getPublic()
//            );
//            certBuilder.addExtension(X509Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));
//
//            JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder("SHA1withRSA");
//            ContentSigner certSigner = certSignerBuilder.build(registererKeyPair.getPrivate());
//            X509CertificateHolder certHolder = certBuilder.build(certSigner);
            X509Certificate requesterCert = getSelfSignedCert(
                    "CN=test-cert, L=test, ST=test, C=RU",
                    "RSA",
                    1024,
                    BigInteger.ONE
            );


            //CSR
            KeyPair keyPair = generateKeys("RSA", 1024);
            PublicKey publicKey = keyPair.getPublic();
            PrivateKey privateKey = keyPair.getPrivate();

            X500Principal requesterSubject = new X500Principal("CN=test-cert, L=Test, ST=tesT, C=RU");

            JcaPKCS10CertificationRequestBuilder csrBuilder =
                    new JcaPKCS10CertificationRequestBuilder(requesterSubject, publicKey);

            DERPrintableString password = new DERPrintableString("11111");
            csrBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_challengePassword, password);

            JcaContentSignerBuilder csrSignerBuilder = new JcaContentSignerBuilder("MD5withRSA");
            ContentSigner csrSigner = csrSignerBuilder.build(privateKey);

            PKCS10CertificationRequest csr = csrBuilder.build(csrSigner);

//            Collection<? extends Certificate> certificates
//                    = jscepClient.getCaCertificate().getCertificates(new X509CertSelector());
//            X509Certificate certificate = (X509Certificate) certificates.stream().findFirst().get();

//            EnrollmentResponse enrol = jscepClient.enrol(certificate, privateKey, csr);

            //REQUEST
//            logger.info("================================================================");
            EnrollmentResponse response = jscepClient.enrol(requesterCert, privateKey, csr);

            System.out.println(response.isSuccess());
//            logger.info("----------------------------------------------------------------");
//            CertStore certStore = response.getCertStore();

//            logger.info("FINISH");


        } catch (NoSuchAlgorithmException |
                OperatorCreationException |
                MalformedURLException |
                ClientException |
                TransactionException |
                CertIOException |
                CertificateException e//|
//                CertStoreException e
        ) {
            e.printStackTrace();
        }

    }

    private static X509Certificate getSelfSignedCert(String name, String instance, int keySize, BigInteger serial)
            throws CertIOException, OperatorCreationException, NoSuchAlgorithmException, CertificateException {
        KeyPair registererKeyPair = generateKeys(instance, keySize);
        X500Principal issuer = new X500Principal(name);
        Calendar calendar = Calendar.getInstance();
        calendar.add(Calendar.DATE, -1);
        Date notBefore = calendar.getTime();
        calendar.add(Calendar.DATE, +2);
        Date notAfter = calendar.getTime();
        X500Principal requester = new X500Principal(name);
        JcaX509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(
                issuer,
                serial,
                notBefore,
                notAfter,
                requester,
                registererKeyPair.getPublic()
        );
        certBuilder.addExtension(X509Extension.keyUsage, false, new KeyUsage(KeyUsage.digitalSignature));

        JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder("MD5withRSA");
        ContentSigner certSigner = certSignerBuilder.build(registererKeyPair.getPrivate());
        X509CertificateHolder certHolder = certBuilder.build(certSigner);

        return new JcaX509CertificateConverter().getCertificate(certHolder);
    }

    private static KeyPair generateKeys(String instance, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(instance);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }
}
