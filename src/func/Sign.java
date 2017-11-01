package func;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.io.StringWriter;
import java.math.BigInteger;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.Principal;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Date;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.asn1.x509.ExtensionsGenerator;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.PrincipalUtil;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;

import gui.*;
import util.CA;
import util.MyKeyStore;

public class Sign {

	private static Object[][] data;

	private static KeyStore mainKeyStore = null;
	private static KeyStore certKeyStore = null;
	private static PKCS10CertificationRequest certificationRequest = null;

	private static class Window extends JFrame {

		JButton buttonGenerate = new JButton("Generate CSR");

		private JTable generateTable() {
			Enumeration<String> aliases = null;
			Enumeration<String> aliasesSigned = null;
			try {

				mainKeyStore = MyKeyStore.getInstance("keyPair");
				certKeyStore = MyKeyStore.getInstance("certificate");

				aliases = mainKeyStore.aliases();
				aliasesSigned = certKeyStore.aliases();

			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			String[] colNames = { "KeyPair Alias" };

			ArrayList<String> lista = new ArrayList();

			try {
				for (Enumeration<String> e = aliases; e != null && e.hasMoreElements();) {
					String alias = e.nextElement();
					if (!certKeyStore.containsAlias(alias))
						lista.add(alias);
				}
			} catch (KeyStoreException e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

			data = new Object[lista.size()][1];
			for (int i = 0; i < lista.size(); i++) {
				data[i][0] = lista.get(i);
			}

			JTable table = new JTable(data, colNames);
			table.setPreferredScrollableViewportSize(new Dimension(500, 70));
			table.setFillsViewportHeight(true);

			ListSelectionModel cellSelectionModel = table.getSelectionModel();
			cellSelectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

			cellSelectionModel.addListSelectionListener(new ListSelectionListener() {

				@Override
				public void valueChanged(ListSelectionEvent e) {
					int row = table.getSelectedRow();
					if (row == -1) {
						buttonGenerate.setEnabled(false);
					}
					buttonGenerate.setEnabled(true);
				}

			});

			return table;
		}

		private void setup() {

			setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
			JTable table = generateTable();
			JPanel panel = new JPanel(new BorderLayout());
			panel.setOpaque(true);
			setContentPane(panel);

			panel.add(new JScrollPane(table), BorderLayout.CENTER);

			JButton buttonBack = new JButton("Back");
			buttonBack.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					dispose();
					StartWin.getFrame().setVisible(true);
				}
			});

			buttonGenerate.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					generateCSR(table.getSelectedRow());
				}
			});
			buttonGenerate.setEnabled(false);

			JPanel buttonPanel = new JPanel(new GridLayout(0, 2));
			buttonPanel.add(buttonBack);
			buttonPanel.add(buttonGenerate);

			panel.add(buttonPanel, BorderLayout.SOUTH);

			setSize(300, 200);
		}

		public Window() {
			super("Certificate Signing");
			setup();

			/*
			 * JButton btnReturn = new JButton("Return");
			 * btnReturn.addActionListener(new ActionListener() { public void
			 * actionPerformed(ActionEvent arg0) { dispose();
			 * StartWin.getFrame().setVisible(true); } });
			 * getContentPane().add(btnReturn, BorderLayout.NORTH); setSize(300,
			 * 200);
			 */
		}
	}

	private static void showDetails(String alias) {
		Certificate cert = null;
		JcaX509CertificateHolder certHolder = null;

		try {
			cert = mainKeyStore.getCertificateChain(alias)[0];
			certHolder = new JcaX509CertificateHolder((X509Certificate) cert);

		} catch (KeyStoreException | CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		X500Name name = certHolder.getSubject();

		JFrame detailWindow = new JFrame("Details");
		detailWindow.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

		JPanel panel = new JPanel(new BorderLayout());

		JLabel title = new JLabel("Details for " + alias);
		title.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 20));
		panel.add(title, BorderLayout.NORTH);

		JPanel subjectPanel = new JPanel(new GridLayout(7, 2, 5, 9));

		subjectPanel.add(new JLabel("Common name (CN=): ", SwingConstants.RIGHT));
		subjectPanel.add(new JLabel(IETFUtils.valueToString(name.getRDNs(BCStyle.CN)[0].getFirst().getValue())));
		subjectPanel.add(new JLabel("Organization (O=): ", SwingConstants.RIGHT));
		subjectPanel.add(new JLabel(IETFUtils.valueToString(name.getRDNs(BCStyle.O)[0].getFirst().getValue())));
		subjectPanel.add(new JLabel("Organization Unit (OU=): ", SwingConstants.RIGHT));
		subjectPanel.add(new JLabel(IETFUtils.valueToString(name.getRDNs(BCStyle.OU)[0].getFirst().getValue())));
		subjectPanel.add(new JLabel("Locality (L=): ", SwingConstants.RIGHT));
		subjectPanel.add(new JLabel(IETFUtils.valueToString(name.getRDNs(BCStyle.L)[0].getFirst().getValue())));
		subjectPanel.add(new JLabel("State (ST=): ", SwingConstants.RIGHT));
		subjectPanel.add(new JLabel(IETFUtils.valueToString(name.getRDNs(BCStyle.ST)[0].getFirst().getValue())));
		subjectPanel.add(new JLabel("Country (C=): ", SwingConstants.RIGHT));
		subjectPanel.add(new JLabel(IETFUtils.valueToString(name.getRDNs(BCStyle.C)[0].getFirst().getValue())));
		subjectPanel.add(new JLabel("E-mail address (E=): ", SwingConstants.RIGHT));
		subjectPanel.add(new JLabel(IETFUtils.valueToString(name.getRDNs(BCStyle.E)[0].getFirst().getValue())));

		subjectPanel.setBorder(BorderFactory.createTitledBorder("Certificate Subject"));

		JPanel certPanel = new JPanel(new GridLayout(0, 2, 5, 5));

		certPanel.add(new JLabel("Serial number: ", SwingConstants.RIGHT));
		certPanel.add(new JLabel("" + certHolder.getSerialNumber()));

		certPanel.add(new JLabel("Valid from: ", SwingConstants.RIGHT));
		certPanel.add(new JLabel("" + certHolder.getNotBefore()));

		certPanel.add(new JLabel("Valid to: ", SwingConstants.RIGHT));
		certPanel.add(new JLabel("" + certHolder.getNotAfter()));

		JButton buttonSign = new JButton("Sign Certificate");
		JButton buttonExtensions = new JButton("Extensions Details");

		buttonSign.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				X509Certificate cert = signCertificate(alias);
				addCertToKeyStore(cert, alias);
				JOptionPane.showMessageDialog(null, "Certificate has been successfully signed");

			}
		});

		buttonExtensions.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				showExtensionsDetails(alias);

			}
		});

		certPanel.add(buttonSign);
		certPanel.add(buttonExtensions);
		// certPanel.add(new JLabel(certHolder.getSignatureAlgorithm())));

		certPanel.setBorder(BorderFactory.createTitledBorder("Certificate Details"));

		panel.add(subjectPanel, BorderLayout.WEST);
		panel.add(certPanel, BorderLayout.EAST);

		detailWindow.add(panel);

		detailWindow.pack();
		detailWindow.setVisible(true);
	}

	protected static void addCertToKeyStore(X509Certificate cert, String alias) {

		try {
			certKeyStore = MyKeyStore.getInstance("certificate");
			certKeyStore.setCertificateEntry(alias, cert);
			MyKeyStore.save("certificate");
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

	}

	private static X509Certificate signCertificate(String alias) {

		try {

			Key key = mainKeyStore.getKey(alias, "password".toCharArray());
			Certificate[] chain = mainKeyStore.getCertificateChain(alias);
			X509Certificate cert = (X509Certificate) chain[0];

			BigInteger serial = cert.getSerialNumber();

			PrivateKey CAPrivateKey = CA.getPrivateKey();

			Date issuedDate = cert.getNotBefore();
			Date expiryDate = cert.getNotAfter();

			JcaPKCS10CertificationRequest jcaRequest = new JcaPKCS10CertificationRequest(certificationRequest);

			X509v3CertificateBuilder certificateBuilder = new JcaX509v3CertificateBuilder(CA.getName(), serial,
					issuedDate, expiryDate, jcaRequest.getSubject(), jcaRequest.getPublicKey());

			ExtensionsGenerator extGen = new ExtensionsGenerator();
			addExtensionsToGenerator(extGen, cert);
			addExtensionsToBuilder(certificateBuilder, extGen.generate());

			ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(CAPrivateKey);

			X509Certificate signedCert = new JcaX509CertificateConverter()
					.getCertificate(certificateBuilder.build(signer));

			return signedCert;

		} catch (Exception e) {
			e.printStackTrace();
		}

		return null;

	}

	private static void addExtensionsToBuilder(X509v3CertificateBuilder certificateBuilder, Extensions allExt)
			throws CertIOException {
		ASN1ObjectIdentifier[] allId = allExt.getExtensionOIDs();
		for (int i = 0; i < allId.length; i++)
			certificateBuilder.addExtension(allExt.getExtension(allId[i]));
	}

	public static void showExtensionsDetails(String alias) {

		X509Certificate cert = null;
		JcaX509CertificateHolder certHolder = null;

		try {
			cert = (X509Certificate) mainKeyStore.getCertificateChain(alias)[0];
			certHolder = new JcaX509CertificateHolder((X509Certificate) cert);

		} catch (KeyStoreException | CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		Set criticalExtensions = certHolder.getCriticalExtensionOIDs();
		Set nonCriticalExtensions = certHolder.getNonCriticalExtensionOIDs();

		JFrame win = new JFrame("Certificate Extensions Details");
		win.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

		JPanel main = new JPanel();

		boolean[] keyUsage = cert.getKeyUsage();
		if (keyUsage == null)
			keyUsage = new boolean[Ext.keyExtensionName.length];
		JPanel keyUsagePanel = new JPanel(new GridLayout(0, 2));
		for (int i = 0; i < Ext.keyExtensionName.length; i++) {
			JCheckBox cb = new JCheckBox(Ext.keyExtensionName[i]);
			cb.setEnabled(false);
			cb.setSelected(keyUsage[i]);
			keyUsagePanel.add(cb);
		}
		JLabel labelKeyUsageCrit;
		if (criticalExtensions.contains(Extension.keyUsage)) {
			labelKeyUsageCrit = new JLabel("Key Usage is marked as critical");
		} else if (nonCriticalExtensions.contains(Extension.keyUsage)) {
			labelKeyUsageCrit = new JLabel("Key Usage is NOT marked as critical");
		} else {
			labelKeyUsageCrit = new JLabel("Key Usage is NOT used");
		}
		keyUsagePanel.add(labelKeyUsageCrit);
		keyUsagePanel.setBorder(BorderFactory.createTitledBorder("Key Usage"));
		main.add(keyUsagePanel);

		JPanel basicPanel = new JPanel(new GridLayout(0, 1));
		int pathLenConstraint = cert.getBasicConstraints();
		if (pathLenConstraint == -1) {
			basicPanel.add(new JLabel("Certificate is not Certificate Authority"));
		} else if (pathLenConstraint == Integer.MAX_VALUE) {
			basicPanel.add(new JLabel("Certificate is Certificate Authority"));
			basicPanel.add(new JLabel("Path Length Constraint: " + "no limit"));
		} else {

			basicPanel.add(new JLabel("Certificate is Certificate Authority"));
			basicPanel.add(new JLabel("Path Length Constraint: " + pathLenConstraint));
		}

		JLabel labelBasicCrit;
		if (criticalExtensions.contains(Extension.basicConstraints)) {
			labelBasicCrit = new JLabel("Basic Constraints is marked as critical");
		} else if (nonCriticalExtensions.contains(Extension.basicConstraints)) {
			labelBasicCrit = new JLabel("Basic Constraints is NOT marked as critical");
		} else {
			labelBasicCrit = new JLabel("Basic Constraints is NOT used");
		}
		basicPanel.add(labelBasicCrit);
		basicPanel.setBorder(BorderFactory.createTitledBorder("Basic Constraints"));
		main.add(basicPanel);

		JPanel altNamesPanel = new JPanel(new GridLayout(0, 1));
		try {
			Collection<List<?>> allNames = cert.getIssuerAlternativeNames();

			if (allNames != null) {
				Iterator<List<?>> it = allNames.iterator();
				while (it.hasNext()) {
					List<?> list = it.next();
					String gName = Ext.getGeneralNameFormatFromTag((int) list.get(0));
					altNamesPanel.add(new JLabel(gName + "   :   " + list.get(1)));

				}
			}
		} catch (CertificateParsingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		JLabel altNamesCrit;
		if (criticalExtensions.contains(Extension.issuerAlternativeName)) {
			altNamesCrit = new JLabel("Issuer Alternative Names is marked as critical");
		} else if (nonCriticalExtensions.contains(Extension.issuerAlternativeName)) {
			altNamesCrit = new JLabel("Issuer Alternative Names is NOT marked as critical");
		} else {
			altNamesCrit = new JLabel("Issuer Alternative Names is NOT used");
		}
		altNamesPanel.add(altNamesCrit);
		altNamesPanel.setBorder(BorderFactory.createTitledBorder("Issuer Alternative Names"));
		main.add(altNamesPanel);

		win.setContentPane(main);
		win.pack();
		win.setVisible(true);

		/*
		 * 
		 * List ext = certHolder.getExtensionOIDs();
		 */

	}

	private static void generateCSR(int row) {
		try {
			char[] password = "password".toCharArray();
			String alias = (String) data[row][0];
			X509Certificate cert = (X509Certificate) mainKeyStore.getCertificateChain(alias)[0];
			PublicKey publicKey = cert.getPublicKey();
			PrivateKey privateKey = (PrivateKey) mainKeyStore.getKey(alias, password);

			
			
			PKCS10CertificationRequestBuilder p10Builder = new JcaPKCS10CertificationRequestBuilder(
					new X500Name(cert.getSubjectX500Principal().getName()), publicKey);
			ExtensionsGenerator extGen = new ExtensionsGenerator();
			addExtensionsToGenerator(extGen, cert);
			p10Builder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
			
			ContentSigner signer = new JcaContentSignerBuilder("SHA1withRSA").build(privateKey);			
			
			
			certificationRequest = p10Builder.build(signer);			
			
			
			StringWriter strWriter = new StringWriter();

			JcaPEMWriter pemWriter = new JcaPEMWriter(strWriter);
			pemWriter.writeObject(certificationRequest);
			pemWriter.close();

			JFileChooser saveFile = new JFileChooser();
			saveFile.setDialogTitle("Save Certificate Signing Request");
			saveFile.setFileFilter(new FileNameExtensionFilter("PKCS #10", "p10", "csr", "pem"));
			int returnVal = saveFile.showSaveDialog(null);

			if (returnVal == JFileChooser.CANCEL_OPTION) {
				JOptionPane.showMessageDialog(null, "Certification Signing Request has not been saved.");
			} else if (returnVal == JFileChooser.APPROVE_OPTION) {
				String path = saveFile.getSelectedFile().getAbsolutePath();
				if (!path.endsWith(".p10") && !path.endsWith(".csr") && !path.endsWith(".pem")) {
					path += ".p10";
				}
				FileWriter fw = new FileWriter(new File(path));
				fw.write(strWriter.toString());
				fw.flush();
				fw.close();
				JOptionPane.showMessageDialog(null, "Certification Signing Request has been saved.");
			}

			showDetails(alias);

		} catch (Exception e) {
			e.printStackTrace();
		}

	}

	private static void addExtensionsToGenerator(ExtensionsGenerator extGen, X509Certificate cert)
			throws IOException, CertificateParsingException {

		JcaX509CertificateHolder certHolder = null;

		try {
			certHolder = new JcaX509CertificateHolder(cert);
		} catch (CertificateEncodingException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

		Set criticalExtensions = certHolder.getCriticalExtensionOIDs();
		Set nonCriticalExtensions = certHolder.getNonCriticalExtensionOIDs();

		boolean[] keyUsage = cert.getKeyUsage();
		int keyUse = 0;

		if (keyUsage != null) {
			for (int i = 0; i < Ext.keyExtensionName.length; i++) {
				if (keyUsage[i]) {
					keyUse |= Ext.getX509KeyUsage(i);
				}
			}
			extGen.addExtension(Extension.keyUsage, criticalExtensions.contains(Extension.keyUsage),
					new KeyUsage(keyUse));
		}

		Collection<List<?>> allNames = cert.getIssuerAlternativeNames();

		if (allNames != null) {
			Iterator<List<?>> it = allNames.iterator();
			GeneralName[] all = new GeneralName[allNames.size()];
			int i = 0;
			while (it.hasNext()) {
				List<?> list = it.next();
				int generalNameFormat = (int) list.get(0);
				String genName = (String) list.get(1);
				all[i++] = new GeneralName(generalNameFormat, genName);
			}
			GeneralNames names = new GeneralNames(all);
			extGen.addExtension(Extension.issuerAlternativeName,
					criticalExtensions.contains(Extension.issuerAlternativeName), names);
		}

		int pathLenConstraint = cert.getBasicConstraints();
		if (pathLenConstraint != -1) {
			extGen.addExtension(Extension.basicConstraints, criticalExtensions.contains(Extension.basicConstraints),
					new BasicConstraints(pathLenConstraint));
		}

	}

	public Sign() {

		StartWin.getFrame().setVisible(false);

		new Window().setVisible(true);
	}
}
