package util;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Date;

import javax.swing.text.html.MinimalHTMLWriter;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;


public class CA {

	private static final long MILLIS_PER_DAY = 86400000l;

	private static X509Certificate certificate = null;
	private static PrivateKey privateKey = null;
	private static final char[] password = "CAPASS".toCharArray();

	private static class CAInfo {
		static String cn = "CA Common name", ou = "CA Organisation Unit", o = "CA Organisation", 
				l = "CA Locality", st = "CA State", c = "CA Country", e = "CA Email";
		static int keyLength = 2048;
		static String serial = "10000000";
		static int validity = 365;
		static int pathLength = 50;

	}

	public static X500Name getName() throws UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException{
		if (certificate == null) load();
		return new X500Name(certificate.getSubjectX500Principal().getName());
	}
	private static X509Certificate createCACert(PublicKey publicKey, PrivateKey privateKey) throws Exception {

		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		builder.addRDN(BCStyle.CN, CAInfo.cn);
		builder.addRDN(BCStyle.O, CAInfo.o);
		builder.addRDN(BCStyle.OU, CAInfo.ou);
		builder.addRDN(BCStyle.L, CAInfo.l);
		builder.addRDN(BCStyle.ST, CAInfo.st);
		builder.addRDN(BCStyle.C, CAInfo.c);
		builder.addRDN(BCStyle.E, CAInfo.e);

		Date issuedDate = new Date();
		Date expiryDate = new Date(System.currentTimeMillis() + CAInfo.validity * MILLIS_PER_DAY);

		X500Name name = builder.build();
		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(name, new BigInteger(CAInfo.serial),
				issuedDate, expiryDate, name, publicKey);

		certGen.addExtension(Extension.basicConstraints, true, new BasicConstraints(CAInfo.pathLength));
		certGen.addExtension(Extension.keyUsage, true,
				new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment));

		ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);

		X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certGen.build(signer));

		return cert;

	}

	private static KeyPairGenerator createKeyPairGenerator(String algorithmIdentifier, int bitCount)
			throws NoSuchProviderException, NoSuchAlgorithmException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance(algorithmIdentifier);
		kpg.initialize(bitCount);
		return kpg;
	}

	private static KeyPair createKeyPair(String encryptionType, int bitCount)
			throws NoSuchProviderException, NoSuchAlgorithmException {
		KeyPairGenerator keyPairGenerator = createKeyPairGenerator(encryptionType, bitCount);
		KeyPair keyPair = keyPairGenerator.genKeyPair();
		return keyPair;
	}

	private static void createAndSetup() {
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("JKS");
			ks.load(null, null);

			KeyPair keyPair = createKeyPair("RSA", CAInfo.keyLength);
			privateKey = keyPair.getPrivate();

			X509Certificate cert = createCACert(keyPair.getPublic(), privateKey);

			Certificate[] chain = new Certificate[1];
			chain[0] = cert;

			ks.setKeyEntry("CA", privateKey, password, chain);

			FileOutputStream fos = new FileOutputStream("store/certauthority.jks");
			ks.store(fos, password);
			fos.close();
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	private static void load() throws NoSuchAlgorithmException, CertificateException, IOException, KeyStoreException, UnrecoverableKeyException {
		KeyStore ks = null;
		try {
			FileInputStream fis = new FileInputStream("store/certauthority.jks");
			ks = KeyStore.getInstance("JKS");
			ks.load(fis, password);
			fis.close();

			privateKey = (PrivateKey) ks.getKey("CA", password);
			certificate = (X509Certificate) ks.getCertificateChain("CA")[0];

		} catch (FileNotFoundException e) {
			e.printStackTrace();
			createAndSetup();
		}
	}

	public static X509Certificate getCertificate()
			throws NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException, UnrecoverableKeyException {
		if (certificate == null)
			load();
		return certificate;
	}

	public static PrivateKey getPrivateKey() throws UnrecoverableKeyException, NoSuchAlgorithmException, CertificateException, KeyStoreException, IOException {
		if (privateKey == null)
			load();
		return privateKey;
	}
}
