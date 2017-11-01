package func;

import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.*;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateParsingException;
import java.security.cert.X509Certificate;
import java.security.interfaces.RSAPublicKey;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Set;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.ASN1String;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.OIDTokenizer;
import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.bouncycastle.asn1.x509.AuthorityKeyIdentifier;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.X509Extension;
import org.bouncycastle.asn1.x509.X509Extensions;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.crypto.tls.SignatureAlgorithm;
import org.bouncycastle.jce.X509KeyUsage;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.SignatureAlgorithmIdentifierFinder;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.ietf.jgss.Oid;
import org.omg.PortableInterceptor.SYSTEM_EXCEPTION;

import gui.*;
import util.MyKeyStore;

public class Overview {

	private static Object[][] data;
	private static ArrayList<JFrame> childFrames = new ArrayList();

	private static KeyStore mainKeyStore = null;
	private static KeyStore certKeyStore = null;

	private static Certificate cert = null;
	private static JcaX509CertificateHolder certHolder = null;

	private static class Window extends JFrame {

		JButton buttonDetails = new JButton("Details");

		private JTable generateTable() {
			Enumeration<String> aliases = null;
			try {

				mainKeyStore = MyKeyStore.getInstance("keyPair");
				certKeyStore = MyKeyStore.getInstance("certificate");

				aliases = mainKeyStore.aliases();

			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			String[] colNames = { "KeyPair Alias", "Signed" };

			ArrayList<String> lista = new ArrayList();
			for (Enumeration<String> e = aliases; e != null && e.hasMoreElements();) {
				lista.add(e.nextElement());
			}

			data = new Object[lista.size()][2];
			for (int i = 0; i < lista.size(); i++) {
				data[i][0] = lista.get(i);
				try {
					data[i][1] = new Boolean(certKeyStore.getCertificate(lista.get(i)) != null);
				} catch (KeyStoreException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
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
						buttonDetails.setEnabled(false);
					}
					buttonDetails.setEnabled(true);
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

			buttonDetails.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					showDetails(table.getSelectedRow());
				}
			});
			buttonDetails.setEnabled(false);

			JPanel buttonPanel = new JPanel(new GridLayout(0, 2));
			buttonPanel.add(buttonBack);
			buttonPanel.add(buttonDetails);

			panel.add(buttonPanel, BorderLayout.SOUTH);

			setSize(300, 200);
		}

		public Window() {
			super("Overview");

			setup();

		}
	}

	private static void showDetails(int row) {
		String alias = (String) data[row][0];
		boolean signed = (Boolean) data[row][1];
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

		certPanel.add(new JLabel("Valid until: ", SwingConstants.RIGHT));
		certPanel.add(new JLabel("" + certHolder.getNotAfter()));

		final RSAPublicKey rsaPk = (RSAPublicKey) cert.getPublicKey();
		int len = rsaPk.getModulus().bitLength();
		String keyAlg = cert.getPublicKey().getAlgorithm() + " " + len + "bits";

		certPanel.add(new JLabel("Public Key: ", SwingConstants.RIGHT));
		JPanel panelKey = new JPanel();
		JButton buttonPublicKey = new JButton("Public Key");
		buttonPublicKey.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				JFrame frame = new JFrame("Public Key");
				frame.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

				JTextArea keyArea = new JTextArea();
				keyArea.setEditable(false);
				StringBuilder sb = new StringBuilder();
				sb.append("0x" + rsaPk.getModulus().toString(16).toUpperCase());

				for (int i = 32; i < sb.length(); i += 33) {
					sb.insert(i, '\n');
				}
				keyArea.setText(sb.toString());
				frame.add(keyArea);
				frame.pack();
				frame.setVisible(true);
			}
		});
		panelKey.add(new JLabel(keyAlg));
		panelKey.add(buttonPublicKey);

		certPanel.add(panelKey);

		JButton buttonSigner = new JButton("Signer Details");
		JButton buttonExtensions = new JButton("Extensions Details");

		buttonSigner.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				showSignerDetails(alias);

			}
		});

		buttonExtensions.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				showExtensionsDetails(alias);

			}
		});

		if (!signed)
			buttonSigner.setEnabled(false);

		certPanel.add(buttonSigner);
		certPanel.add(buttonExtensions);
		// certPanel.add(new JLabel(certHolder.getSignatureAlgorithm())));

		certPanel.setBorder(BorderFactory.createTitledBorder("Certificate Details"));

		panel.add(subjectPanel, BorderLayout.WEST);
		panel.add(certPanel, BorderLayout.EAST);

		detailWindow.add(panel);

		detailWindow.pack();
		detailWindow.setVisible(true);
	}

	private static void showSignerDetails(String alias) {
		KeyStore certKS;
		JcaX509CertificateHolder certHolder = null;
		Certificate cert = null;
		try {
			certKS = MyKeyStore.getInstance("certificate");
			cert = certKS.getCertificate(alias);
			certHolder = new JcaX509CertificateHolder((X509Certificate) cert);
			
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
		X500Name issuerName = certHolder.getIssuer();

		JFrame detailWindow = new JFrame("Signature Details");
		detailWindow.setDefaultCloseOperation(WindowConstants.DISPOSE_ON_CLOSE);

		JPanel panel = new JPanel();


		JPanel issuerPanel = new JPanel(new GridLayout(7, 2, 5, 9));

		issuerPanel.add(new JLabel("Common name (CN=): ", SwingConstants.RIGHT));
		issuerPanel.add(new JLabel(IETFUtils.valueToString(issuerName.getRDNs(BCStyle.CN)[0].getFirst().getValue())));
		issuerPanel.add(new JLabel("Organization (O=): ", SwingConstants.RIGHT));
		issuerPanel.add(new JLabel(IETFUtils.valueToString(issuerName.getRDNs(BCStyle.O)[0].getFirst().getValue())));
		issuerPanel.add(new JLabel("Organization Unit (OU=): ", SwingConstants.RIGHT));
		issuerPanel.add(new JLabel(IETFUtils.valueToString(issuerName.getRDNs(BCStyle.OU)[0].getFirst().getValue())));
		issuerPanel.add(new JLabel("Locality (L=): ", SwingConstants.RIGHT));
		issuerPanel.add(new JLabel(IETFUtils.valueToString(issuerName.getRDNs(BCStyle.L)[0].getFirst().getValue())));
		issuerPanel.add(new JLabel("State (ST=): ", SwingConstants.RIGHT));
		issuerPanel.add(new JLabel(IETFUtils.valueToString(issuerName.getRDNs(BCStyle.ST)[0].getFirst().getValue())));
		issuerPanel.add(new JLabel("Country (C=): ", SwingConstants.RIGHT));
		issuerPanel.add(new JLabel(IETFUtils.valueToString(issuerName.getRDNs(BCStyle.C)[0].getFirst().getValue())));
		issuerPanel.add(new JLabel("E-mail address (E=): ", SwingConstants.RIGHT));
		issuerPanel.add(new JLabel(IETFUtils.valueToString(issuerName.getRDNs(BCStyle.E)[0].getFirst().getValue())));

		issuerPanel.setBorder(BorderFactory.createTitledBorder("Certificate Issuer"));
		
		panel.add(issuerPanel, BorderLayout.WEST);
		
		JPanel signaturePanel = new JPanel(new BorderLayout());
		signaturePanel.add(new JLabel ("Signature Algorithm : SHA-1 with RSA Encryption"), BorderLayout.NORTH);
		
		JTextArea signatureArea = new JTextArea(5, 20);
		signatureArea.setEditable(false);
		
		StringBuilder sb = new StringBuilder();
		byte[] signature = certHolder.getSignature();
		
		for (int i = 0; i < signature.length; i++){
			int b = signature[i];
			if (b < 0) b += 256;
			if (i % 8 == 0 && i > 0) sb.append('\n');
			sb.append(Integer.toHexString(b) + " ");
		}
		signatureArea.setText(sb.toString());
		JScrollPane scroll = new JScrollPane(signatureArea);		
		signaturePanel.add(scroll);
		
		
		panel.add(signaturePanel);
		
		detailWindow.add(panel);
		detailWindow.pack();
		detailWindow.setVisible(true);
	}

	private static void showExtensionsDetails(String alias) {

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

	}

	public Overview() {

		StartWin.getFrame().setVisible(false);

		new Window().setVisible(true);
	}
}
