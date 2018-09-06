import org.bouncycastle.asn1.DERPrintableString;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.jscep.client.Client;
import org.jscep.client.ClientException;
import org.jscep.client.DefaultCallbackHandler;
import org.jscep.client.EnrollmentResponse;
import org.jscep.transaction.TransactionException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.security.auth.x500.X500Principal;
import java.math.BigInteger;
import java.net.MalformedURLException;
import java.net.URL;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

/**
 * Good guide for DogTag installation on CentOS: https://magnus-k-karlsson.blogspot.com/2017/11/installing-and-testing-dogtag.html
 * SCEP enable: http://www.dogtagpki.org/wiki/SCEP_Setup
 * Original JSCEP guide: https://github.com/jscep/jscep
 */
public class JscepSandbox {

    private final static Logger logger = LoggerFactory.getLogger(JscepSandbox.class);

    private final static String RSA = "RSA";
    private final static String SHA256withRSA = "SHA256withRSA";
    private final static String SHA512withRSA = "SHA512withRSA";
    private final static String SHA1withRSA = "SHA1withRSA";
    private final static String MD5withRSA = "MD5withRSA";

    private final static String SCEP_DOGTAG = "http://[enter_your_dogtag_host]:8080/ca/cgi-bin/pkiclient.exe";

    public static void main(String[] args) {
        try {

            URL url = new URL(SCEP_DOGTAG);
            Client jscepClient = new Client(
                    url,
                    //TODO: write something better
                    new DefaultCallbackHandler(x509Certificate -> true)
            );

            KeyPair requesterKeyPair = generateKeys(RSA, 1024);
            X500Principal requesterIssuer = new X500Principal("CN=test.org, L=test, ST=test, C=UK");
            BigInteger serial = BigInteger.ONE;
            Calendar calendar = Calendar.getInstance();
            calendar.add(Calendar.DATE, -1); // yesterday
            Date notBefore = calendar.getTime();
            calendar.add(Calendar.DATE, +2); // tomorrow
            Date notAfter = calendar.getTime();
            X500Principal requesterSubject = new X500Principal("CN=test.org, L=test, ST=test, C=UK");

            X509Certificate requesterCert = generateSelfSignedCert(
                    requesterIssuer, serial, notBefore, notAfter, requesterSubject, requesterKeyPair, SHA256withRSA
            );

            KeyPair entityKeyPair = generateKeys(RSA, 1024);
            // On dogtag host: /var/lib/pki/pki-tomcat/ca/conf/flatfile.txt field PWD
            PKCS10CertificationRequest csr = buildCSR(requesterSubject, entityKeyPair, "11111");

            EnrollmentResponse response = jscepClient.enrol(requesterCert, requesterKeyPair.getPrivate(), csr);
            logger.info(response.isSuccess() + "");

        } catch (MalformedURLException
                | NoSuchAlgorithmException
                | OperatorCreationException
                | CertificateException
                | TransactionException
                | ClientException
                e
        ) {
            logger.error(e.getMessage(), e);
        }

    }

    private static PKCS10CertificationRequest buildCSR(
            X500Principal entitySubject,
            KeyPair entityKeyPair,
            String password
    ) throws OperatorCreationException {

        PKCS10CertificationRequestBuilder csrBuilder =
                new JcaPKCS10CertificationRequestBuilder(entitySubject, entityKeyPair.getPublic());
        csrBuilder.addAttribute(
                PKCSObjectIdentifiers.pkcs_9_at_challengePassword,
                new DERPrintableString(password)
        );
        JcaContentSignerBuilder csrSignerBuilder = new JcaContentSignerBuilder(SHA1withRSA);
        ContentSigner csrSigner = csrSignerBuilder.build(entityKeyPair.getPrivate());

        return csrBuilder.build(csrSigner);
    }

    private static X509Certificate generateSelfSignedCert(
            X500Principal requesterIssuer,
            BigInteger serial,
            Date notBefore,
            Date notAfter,
            X500Principal requesterSubject,
            KeyPair requesterKeyPair,
            String algorithm
    ) throws OperatorCreationException, CertificateException {

        JcaX509v3CertificateBuilder certBuilder =
                new JcaX509v3CertificateBuilder(
                        requesterIssuer,
                        serial,
                        notBefore,
                        notAfter,
                        requesterSubject,
                        requesterKeyPair.getPublic()
                );
        PrivateKey requesterPrivKey = requesterKeyPair.getPrivate();
        JcaContentSignerBuilder certSignerBuilder = new JcaContentSignerBuilder(algorithm);
        ContentSigner certSigner = certSignerBuilder.build(requesterPrivKey);
        X509CertificateHolder certHolder = certBuilder.build(certSigner);
        JcaX509CertificateConverter converter = new JcaX509CertificateConverter();

        return converter.getCertificate(certHolder);
    }

    private static KeyPair generateKeys(String instance, int keySize) throws NoSuchAlgorithmException {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(instance);
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }
}
