package func;

import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.awt.event.ItemEvent;
import java.awt.event.ItemListener;
import java.io.IOException;
import java.util.ArrayList;

import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.table.AbstractTableModel;

import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.CertIOException;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.jce.X509KeyUsage;

public class Ext {

	// Key Usage
	private JCheckBox[] keyExt = new JCheckBox[9];
	public static final String keyExtensionName[] = { "Digital Signature", "Non Repudiation", "Key Enchipherment",
			"Data Enchipherment", "Key Agreement", "Certificate Signing", "CRL Signing", "Encipher Only",
			"Decipher Only" };
	private JCheckBox keyCritical = new JCheckBox("Key Usage extensions are marked as critical");
	// End Key Usage

	// Issuer Alternative Names
	private ArrayList<GeneralName> issuerAltNames = new ArrayList<GeneralName>();
	private static final String issuerAltGeneralNames[] = { "rfc822Name", "iPAddress", "directoryName", "dNSName",
			"uniformResourceIdentifier", "registeredID" };
	private JTextField inputAltName = new JTextField();
	private JButton buttonAdd = new JButton("Add"), buttonAll = new JButton("Show all");
	private JComboBox altNamesComboBox;
	private JCheckBox altNamesCritical = new JCheckBox("Issuer Alternative Names extensions are marked as critical");
	// End Issuer Alternative Names

	// Basic Constraints
	private JCheckBox cA = new JCheckBox("Certificate Authority");
	private JTextField pathLengthTextField = new JTextField();
	private JCheckBox basicConstraintsCritical = new JCheckBox("Basic Constraints extensions are marked as critical");
	private JCheckBox useBasicConstraints = new JCheckBox("Use Basic Constraints Extension");
	// End Basic Constraints

	private static Win window;

	private class Win extends JFrame {

		public Win() {
			super("Certificate Extensions");

			setup();

		}

		void setup() {

			getContentPane().setLayout(new BoxLayout(this.getContentPane(), BoxLayout.LINE_AXIS));

			JPanel borderPanel1 = new JPanel(new BorderLayout());
			JPanel gridPanel1 = new JPanel(new GridLayout(5, 2));

			for (int i = 0; i < keyExt.length; i++) {
				keyExt[i] = new JCheckBox(keyExtensionName[i], false);
				gridPanel1.add(keyExt[i]);
			}

			gridPanel1.setBorder(BorderFactory.createTitledBorder("Key Usage"));
			borderPanel1.add(gridPanel1, BorderLayout.NORTH);
			borderPanel1.add(keyCritical, BorderLayout.CENTER);
			// borderPanel1.add(new JLabel(" "), BorderLayout.SOUTH);

			JPanel borderPanel2 = new JPanel(new BorderLayout());

			JPanel altNamePanel = new JPanel(new GridLayout(0, 2));
			altNamesComboBox = new JComboBox(issuerAltGeneralNames);

			buttonAdd.setEnabled(false);

			altNamePanel.add(altNamesComboBox);
			altNamePanel.add(inputAltName);
			altNamePanel.add(buttonAdd);
			altNamePanel.add(buttonAll);
			borderPanel2.add(altNamePanel, BorderLayout.NORTH);

			borderPanel2.setBorder(BorderFactory.createTitledBorder("Issuer Alternative Names"));
			borderPanel2.add(altNamesCritical, BorderLayout.CENTER);

			inputAltName.getDocument().addDocumentListener(new DocumentListener() {
				@Override
				public void removeUpdate(DocumentEvent e) {
					warn();
				}

				@Override
				public void insertUpdate(DocumentEvent e) {
					warn();
				}

				@Override
				public void changedUpdate(DocumentEvent e) {
					warn();
				}

				public void warn() {
					int arg0 = getGeneralNameFormat();
					String text = inputAltName.getText();
					try {
						GeneralName altName = new GeneralName(arg0, text);
					} catch (Exception e) {
						buttonAdd.setEnabled(false);
						return;
					}
					if (!text.isEmpty())
						buttonAdd.setEnabled(true);
					else
						buttonAdd.setEnabled(false);

				}
			});

			altNamesComboBox.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					String text = inputAltName.getText();
					inputAltName.setText(text);
				}
			});

			buttonAdd.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					int arg0 = getGeneralNameFormat();
					String altName = inputAltName.getText();
					issuerAltNames.add(new GeneralName(arg0, altName));
					JOptionPane.showMessageDialog(window, "Alternative name " + altName + " successfully added.");
				}
			});

			buttonAll.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					new AltNamesPreview().setVisible(true);

				}
			});

			JPanel borderPanel3 = new JPanel(new BorderLayout());
			JPanel borderPanel4 = new JPanel(new BorderLayout());

			useBasicConstraints.setSelected(false);
			cA.setEnabled(false);
			pathLengthTextField.setEditable(false);
			keyExt[5].setSelected(false);
			keyExt[5].setEnabled(false);

			basicConstraintsCritical.setEnabled(false);
			useBasicConstraints.addItemListener(new ItemListener() {

				@Override
				public void itemStateChanged(ItemEvent e) {
					if (e.getStateChange() == ItemEvent.SELECTED) {
						cA.setEnabled(true);
						if (cA.isSelected()) {
							pathLengthTextField.setEditable(true);
							keyExt[5].setSelected(true);
						}
						basicConstraintsCritical.setEnabled(true);

					} else if (e.getStateChange() == ItemEvent.DESELECTED) {
						cA.setEnabled(false);
						pathLengthTextField.setEditable(false);
						keyExt[5].setSelected(false);

						basicConstraintsCritical.setEnabled(false);
					}
				}
			});
			cA.addItemListener(new ItemListener() {

				@Override
				public void itemStateChanged(ItemEvent e) {
					if (e.getStateChange() == ItemEvent.SELECTED) {
						pathLengthTextField.setEditable(true);
						keyExt[5].setSelected(true);
					} else if (e.getStateChange() == ItemEvent.DESELECTED) {
						pathLengthTextField.setEditable(false);
						keyExt[5].setSelected(false);
					}
				}
			});

			JPanel gPanel = new JPanel(new GridLayout(0, 1));
			gPanel.add(useBasicConstraints);
			gPanel.add(cA);
			borderPanel3.add(gPanel, BorderLayout.NORTH);

			borderPanel3.add(new JLabel("pathLenConstraint  "), BorderLayout.WEST);
			borderPanel3.add(pathLengthTextField, BorderLayout.CENTER);
			borderPanel3.add(basicConstraintsCritical, BorderLayout.SOUTH);

			borderPanel3.setBorder(BorderFactory.createTitledBorder("Basic Constraints"));

			borderPanel4.add(borderPanel2, BorderLayout.NORTH);
			borderPanel4.add(borderPanel3, BorderLayout.CENTER);

			JButton buttonClose = new JButton("Close");
			buttonClose.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					window.setVisible(false);

				}
			});

			borderPanel1.add(buttonClose, BorderLayout.SOUTH);
			add(borderPanel1);
			add(borderPanel4);

			pack();
		}
	}

	private class AltNamesPreview extends JFrame {
		JPanel panel;

		private void reset() {
			getContentPane().removeAll();
			setup();
			validate();
		}

		private void setup() {
			this.setSize(330, 200);
			panel = new JPanel(new BorderLayout());

			Object[][] data = new Object[issuerAltNames.size()][2];
			GeneralName it;
			for (int i = 0; i < issuerAltNames.size(); i++) {
				it = issuerAltNames.get(i);
				data[i][0] = getGeneralNameFormatFromTag(it.getTagNo());
				data[i][1] = it.getName();
			}

			String[] colNames = { "Format", "Alternative Name" };

			JTable table = new JTable(data, colNames);
			ListSelectionModel cellSelectionModel = table.getSelectionModel();
			cellSelectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

			panel.setOpaque(true);
			setContentPane(panel);

			panel.add(new JScrollPane(table), BorderLayout.CENTER);

			JButton buttonDelete = new JButton("Delete");
			panel.add(buttonDelete, BorderLayout.SOUTH);
			buttonDelete.setEnabled(false);
			buttonDelete.addActionListener(new ActionListener() {
				@Override
				public void actionPerformed(ActionEvent e) {
					int row = table.getSelectedRow();
					issuerAltNames.remove(row);
					reset();
				}
			});

			cellSelectionModel.addListSelectionListener(new ListSelectionListener() {

				@Override
				public void valueChanged(ListSelectionEvent e) {
					int row = table.getSelectedRow();
					if (row == -1) {
						buttonDelete.setEnabled(false);
					}
					buttonDelete.setEnabled(true);
				}

			});
		}

		public AltNamesPreview() {
			super("Issuer Alternative Names Preview");
			setup();
		}
	}

	public void hide() {
		window.setVisible(false);
	}

	public void show() {
		window.setVisible(true);
	}

	public Ext() {
		window = new Win();
	}
	


	public static String getGeneralNameFormatFromTag(int tag) {
		switch (tag) {
		case 1:
			return "rfc822Name";
		case 2:
			return "dNSName";
		case 4:
			return "directoryName";
		case 6:
			return "uniformResourceIdentifier";
		case 7:
			return "iPAddress";
		case 8:
			return "registeredID";
		}
		return null;
	}

	private int getGeneralNameFormat() {
		switch (altNamesComboBox.getSelectedIndex()) {
		case 0:
			return GeneralName.rfc822Name;
		case 1:
			return GeneralName.iPAddress;
		case 2:
			return GeneralName.directoryName;
		case 3:
			return GeneralName.dNSName;
		case 4:
			return GeneralName.uniformResourceIdentifier;
		case 5:
			return GeneralName.registeredID;
		}
		return -1;
	}

	public static int getX509KeyUsage(int i) {
		switch (i) {
		case 0:
			return X509KeyUsage.digitalSignature;
		case 1:
			return X509KeyUsage.nonRepudiation;
		case 2:
			return X509KeyUsage.keyEncipherment;
		case 3:
			return X509KeyUsage.dataEncipherment;
		case 4:
			return X509KeyUsage.keyAgreement;
		case 5:
			return X509KeyUsage.keyCertSign;
		case 6:
			return X509KeyUsage.cRLSign;
		case 7:
			return X509KeyUsage.encipherOnly;
		case 8:
			return X509KeyUsage.decipherOnly;
		}
		return 0;
	}

	public void addExtensionsToCert(X509v3CertificateBuilder certGen) throws CertIOException, IOException {
		// Adding keyusage extension
		int keyUsage = 0;
		boolean critical = keyCritical.isSelected();

		for (int i = 0; i < keyExt.length; i++) {
			if (keyExt[i].isSelected() && keyExt[i].isEnabled()) {
				keyUsage |= getX509KeyUsage(i);
			}
		}
		if (keyUsage != 0) {
			X509KeyUsage keyuse = new X509KeyUsage(keyUsage);
			certGen.addExtension(Extension.keyUsage, critical, keyuse.getEncoded());
		}
		// end adding keyusage extension

		// Issuer alternative names
		critical = altNamesCritical.isSelected();
		if (issuerAltNames.size() > 0) {
			GeneralName[] all = new GeneralName[issuerAltNames.size()];
			int i = 0;
			for (GeneralName it : issuerAltNames) {
				all[i++] = it;
			}
			GeneralNames names = new GeneralNames(all);
			certGen.addExtension(Extension.issuerAlternativeName, critical, names);
		}
		// end issuer alt names

		// Basic constraints ext
		if (useBasicConstraints.isSelected()) {
			critical = basicConstraintsCritical.isSelected();
			if (cA.isSelected()) {
				int length = Integer.parseInt(pathLengthTextField.getText());
				certGen.addExtension(Extension.basicConstraints, critical, new BasicConstraints(length));
			} else {
				certGen.addExtension(Extension.basicConstraints, critical, new BasicConstraints(false));
			}
		}
		// end basic constraints

	}

}
