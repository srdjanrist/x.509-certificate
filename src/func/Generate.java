package func;

import java.awt.*;
import java.awt.event.*;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.KeyStore.PrivateKeyEntry;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.Extension;
import java.security.cert.X509Certificate;
import java.text.*;
import java.util.*;

import javax.swing.*;

import gui.*;
import util.MyKeyStore;

import javax.swing.GroupLayout.Alignment;
import javax.swing.JFormattedTextField.AbstractFormatter;
import javax.swing.LayoutStyle.ComponentPlacement;
import javax.swing.border.Border;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.*;
import org.bouncycastle.asn1.x500.style.*;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.*;
import org.bouncycastle.jce.*;
import org.bouncycastle.jce.provider.*;
import org.bouncycastle.operator.*;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.x509.X509V3CertificateGenerator;
import org.jdatepicker.impl.*;
import org.jdatepicker.util.*;

public class Generate {

	private static Win window;

	private Ext extensions = new Ext();

	private X509Certificate createCACert(PublicKey publicKey, PrivateKey privateKey) throws Exception {

		X500NameBuilder builder = new X500NameBuilder(BCStyle.INSTANCE);
		builder.addRDN(BCStyle.CN, SubjectInfo.cn);
		builder.addRDN(BCStyle.O, SubjectInfo.o);
		builder.addRDN(BCStyle.OU, SubjectInfo.ou);
		builder.addRDN(BCStyle.L, SubjectInfo.l);
		builder.addRDN(BCStyle.ST, SubjectInfo.st);
		builder.addRDN(BCStyle.C, SubjectInfo.c);
		builder.addRDN(BCStyle.E, SubjectInfo.e);

		ContentSigner sigGen = new JcaContentSignerBuilder("SHA1WithRSA").build(privateKey);

		X509v3CertificateBuilder certGen = new JcaX509v3CertificateBuilder(builder.build(),
				new BigInteger(window.serial.getText()), window.dateFrom, window.dateTo, builder.build(), publicKey);

		extensions.addExtensionsToCert(certGen);

		X509Certificate cert = new JcaX509CertificateConverter().getCertificate(certGen.build(sigGen));

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

	private static class SubjectInfo {
		static String cn, ou, o, l, st, c, e;
	}

	private void generateKeyPair(String name) {
		SubjectInfo.cn = window.cn.getText();
		SubjectInfo.ou = window.ou.getText();
		SubjectInfo.o = window.o.getText();
		SubjectInfo.l = window.l.getText();
		SubjectInfo.st = window.st.getText();
		SubjectInfo.c = window.c.getText();
		SubjectInfo.e = window.e.getText();

		String keyLength = (String) window.keyLength.getSelectedItem();

		try {
			KeyPair keyPair = createKeyPair("RSA", Integer.parseInt(keyLength));

			PrivateKey prk = keyPair.getPrivate();
			PublicKey puk = keyPair.getPublic();

			try {
				char[] password = "password".toCharArray();

				KeyStore ks = MyKeyStore.getInstance("keyPair");

				Certificate cert = createCACert(puk, prk);
				Certificate[] chain = new Certificate[1];
				chain[0] = cert;

				ks.setKeyEntry(name, prk, password, chain);

				MyKeyStore.save("keyPair");

				JOptionPane.showMessageDialog(window, "Key Pair successfully stored in KeyStore under name : " + name);

			} catch (FileNotFoundException e) {
				e.printStackTrace();
			} catch (Exception e1) {
				// TODO Auto-generated catch block
				e1.printStackTrace();
			}

		} catch (NoSuchProviderException | NoSuchAlgorithmException e1) {
			// TODO Auto-generated catch block
			e1.printStackTrace();
		}

	}

	private class Win extends JFrame {
		public JTextField cn = new JTextField(), ou = new JTextField(), o = new JTextField(), l = new JTextField(),
				st = new JTextField(), c = new JTextField(), e = new JTextField(), serial = new JTextField();
		public JComboBox<String> keyLength;
		public Date dateTo = null, dateFrom = null;

		public Win() {
			super("Key pair generator");

			setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
			getContentPane().setLayout(new BorderLayout(0, 0));

			JPanel panel = new JPanel();

			panel.setLayout(new GridLayout(7, 2, 5, 9));
			getContentPane().add(panel, BorderLayout.CENTER);

			panel.add(new JLabel("Common name (CN=): ", SwingConstants.RIGHT));
			panel.add(cn);
			panel.add(new JLabel("Organization (O=): ", SwingConstants.RIGHT));
			panel.add(o);
			panel.add(new JLabel("Organization Unit (OU=): ", SwingConstants.RIGHT));
			panel.add(ou);
			panel.add(new JLabel("Locality (L=): ", SwingConstants.RIGHT));
			panel.add(l);
			panel.add(new JLabel("State (ST=): ", SwingConstants.RIGHT));
			panel.add(st);
			panel.add(new JLabel("Country (C=): ", SwingConstants.RIGHT));
			panel.add(c);
			panel.add(new JLabel("E-mail address (E=): ", SwingConstants.RIGHT));
			panel.add(e);

			panel.setBorder(BorderFactory.createTitledBorder("Certificate Subject"));

			JPanel panel2 = new JPanel(new GridLayout(0, 2, 5, 5));

			panel2.add(new JLabel("Serial number: ", SwingConstants.RIGHT));
			panel2.add(serial);
			String[] lengths = { "512", "1024", "2048", "4096" };
			keyLength = new JComboBox(lengths);
			keyLength.setSelectedIndex(0);
			// box.setMaximumRowCount(1);
			panel2.add(new JLabel("Key Length: ", SwingConstants.RIGHT));
			Panel test = new Panel(new GridLayout(0, 2));
			test.add(keyLength);
			test.add(new Label("bits"));
			panel2.add(test);

			panel2.add(new JLabel("Certificate version: ", SwingConstants.RIGHT));
			String[] versions = { "v3" };
			JComboBox box2 = new JComboBox(versions);
			panel2.add(box2);

			panel2.add(new JLabel("Valid from: ", SwingConstants.RIGHT));

			UtilDateModel model = new UtilDateModel();

			Properties p = new Properties();

			p.put("text.today", "Today");
			p.put("text.month", "Month");
			p.put("text.year", "Year");
			JDatePanelImpl datePanel = new JDatePanelImpl(model, p);

			JDatePickerImpl datePicker = new JDatePickerImpl(datePanel, new AbstractFormatter() {
				private String datePattern = "yyyy-MM-dd";
				private SimpleDateFormat dateFormatter = new SimpleDateFormat(datePattern);

				@Override
				public Object stringToValue(String text) throws ParseException {
					return dateFormatter.parseObject(text);
				}

				@Override
				public String valueToString(Object value) throws ParseException {
					if (value != null) {
						Calendar cal = (Calendar) value;
						return dateFormatter.format(cal.getTime());
					}
					return "";
				}
			});
			datePicker.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					dateFrom = (Date) datePicker.getModel().getValue();
				}
			});

			panel2.add(datePicker);

			panel2.add(new JLabel("Valid until: ", SwingConstants.RIGHT));

			UtilDateModel model2 = new UtilDateModel();

			Properties p2 = new Properties();

			p2.put("text.today", "Today");
			p2.put("text.month", "Month");
			p2.put("text.year", "Ycear");
			JDatePanelImpl datePanel2 = new JDatePanelImpl(model2, p2);

			JDatePickerImpl datePicker2 = new JDatePickerImpl(datePanel2, new AbstractFormatter() {
				private String datePattern = "yyyy-MM-dd";
				private SimpleDateFormat dateFormatter = new SimpleDateFormat(datePattern);

				@Override
				public Object stringToValue(String text) throws ParseException {
					return dateFormatter.parseObject(text);
				}

				@Override
				public String valueToString(Object value) throws ParseException {
					if (value != null) {
						Calendar cal = (Calendar) value;
						return dateFormatter.format(cal.getTime());
					}
					return "";
				}
			});

			datePicker2.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					dateTo = (Date) datePicker2.getModel().getValue();
				}
			});

			panel2.add(datePicker2);

			JPanel panel3 = new JPanel(new BorderLayout());
			panel3.add(panel2, BorderLayout.NORTH);
			JButton ext = new JButton("Extensions...");
			ext.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					extensions.show();

				}
			});
			panel3.add(ext, BorderLayout.SOUTH);

			panel3.setBorder(BorderFactory.createTitledBorder("Certificate Options"));

			getContentPane().add(panel3, BorderLayout.EAST);

			JButton keygen = new JButton("Generate key pair");
			keygen.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent ev) {
					if (cn.getText().trim().equals("") || ou.getText().trim().equals("")
							|| o.getText().trim().equals("") || l.getText().trim().equals("")
							|| st.getText().trim().equals("") || c.getText().trim().equals("")
							|| e.getText().trim().equals("") || serial.getText().trim().equals("") || dateTo == null
							|| dateFrom == null) {

						JOptionPane.showMessageDialog(window, "All fields must be filled.");
					} else {
						String s = (String) JOptionPane.showInputDialog(null, "Enter name for Key Pair",
								"Name of Key Pair", JOptionPane.PLAIN_MESSAGE, null, null, null);

						// If a string was returned, say so.
						if (s == null || (s != null && ("".equals(s)))) {
							return;
						}
						if ((s != null) && (s.length() > 0)) {
							generateKeyPair(s);
							return;
						}
					}
				}
			});

			JButton buttonReturn = new JButton("Back");
			buttonReturn.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					window.setVisible(false);
					window.dispose();
					StartWin.getFrame().setVisible(true);
				}
			});

			Panel pb = new Panel(new GridLayout(0, 5));
			pb.add(new Label(""));
			pb.add(keygen);
			pb.add(new Label(""));
			pb.add(buttonReturn);
			getContentPane().add(pb, BorderLayout.SOUTH);

			pack();

		}
	}

	public Generate() {
		StartWin.getFrame().setVisible(false);

		window = new Win();
		window.setVisible(true);

	}
}
