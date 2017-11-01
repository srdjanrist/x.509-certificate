package func.keyEI;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Enumeration;

import javax.crypto.spec.SecretKeySpec;
import javax.swing.*;
import javax.swing.border.Border;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;

import util.MyKeyStore;

class KeyPairExport extends JFrame {

	private String[][]mainAliases=null;
	private JTable table;
	private KeyStore mainKeyStore;
	private JFrame rtnFrame, thisFrame;
	private JButton buttonCont = new JButton("Continue");

	private JTable generateTable() {
		Enumeration<String>aliases = null;
		try {
			
			mainKeyStore = MyKeyStore.getInstance("keyPair");

			aliases = mainKeyStore.aliases();

		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}

		String[] colNames = { "KeyPair Alias" };

		ArrayList<String> lista = new ArrayList();
		for (Enumeration<String> e = aliases; e != null && e.hasMoreElements();) {
			lista.add(e.nextElement());
		}
		mainAliases = new String[lista.size()][1];
		for (int i = 0; i < lista.size(); i++) {
			mainAliases[i][0] = lista.get(i);
		}

		table = new JTable(mainAliases, colNames);
		table.setPreferredScrollableViewportSize(new Dimension(500, 70));
		table.setFillsViewportHeight(true);

		ListSelectionModel cellSelectionModel = table.getSelectionModel();
		cellSelectionModel.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
		
		cellSelectionModel.addListSelectionListener(new ListSelectionListener() {

			@Override
			public void valueChanged(ListSelectionEvent e) {
				int row = table.getSelectedRow();
				if (row == -1) {
					buttonCont.setEnabled(false);
				}
				buttonCont.setEnabled(true);
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
				thisFrame.dispose();
				rtnFrame.setVisible(true);
			}
		});
		buttonCont.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {
				exportKeyPair();
			}
		});
		buttonCont.setEnabled(false);

		JPanel buttonPanel = new JPanel(new GridLayout(0, 2));
		buttonPanel.add(buttonBack);
		buttonPanel.add(buttonCont);

		panel.add(buttonPanel, BorderLayout.SOUTH);

		setSize(300, 200);
	}

	protected void exportKeyPair() {
		JFileChooser chooser = new JFileChooser();
		FileNameExtensionFilter filter = new FileNameExtensionFilter("PKCS #12", "p12");
		chooser.setFileFilter(filter);
		int returnVal = chooser.showSaveDialog(getContentPane());
		if (returnVal == JFileChooser.APPROVE_OPTION) {
			String path = chooser.getSelectedFile().getAbsolutePath();
			JPanel panel = new JPanel();
			JLabel label = new JLabel("Enter a password:");
			JPasswordField pass = new JPasswordField(15);
			panel.add(label);
			panel.add(pass);

			char[] password;

			while (true) {
				int option = JOptionPane.showOptionDialog(null, panel, "Password for KeyPair protection",
						JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, null, null);
				if (option == JOptionPane.OK_OPTION) {
					password = pass.getPassword();
					if (password.length == 0)
						JOptionPane.showMessageDialog(null, "Password must contain at least 1 character");
					else
						break;
				} else if (option == JOptionPane.CANCEL_OPTION)
					return;
			}

			/*
			 * Pokusaj enkriptovanja zastite fajla sa AES byte[] key;
			 * SecretKeySpec secretKeySpec; try { key =
			 * password.toString().getBytes("UTF-8"); MessageDigest sha =
			 * MessageDigest.getInstance("SHA-1"); key = sha.digest(key); key =
			 * Arrays.copyOf(key, 16); // use only first 128 bit secretKeySpec =
			 * new SecretKeySpec(key, "AES"); } catch
			 * (UnsupportedEncodingException | NoSuchAlgorithmException e) {
			 * e.printStackTrace(); }
			 */

			try {
				KeyStore keyStore = KeyStore.getInstance("PKCS12");
				keyStore.load(null, null);

				
				int row = table.getSelectedRow();
				String chosenAlias = mainAliases[row][0];
				
				Key key = mainKeyStore.getKey(chosenAlias, "password".toCharArray());
				Certificate[] chain = mainKeyStore.getCertificateChain(chosenAlias);
				
				keyStore.setKeyEntry(chosenAlias, key, password, chain);			
				
				FileOutputStream os = new FileOutputStream(path.endsWith(".p12") ? path : path +".p12");
				keyStore.store(os, password);
				
				os.close();
				
				JOptionPane.showMessageDialog(null, "Key Pair has been successfully exported");

			} catch (Exception ex) {
				ex.printStackTrace();
			}

		}
	}

	public KeyPairExport(JFrame rtnFrame) {
		super("Key Pair Export");
		this.rtnFrame = rtnFrame;
		thisFrame = this;
		setup();

		rtnFrame.setVisible(false);
		this.setVisible(true);
	}

}
