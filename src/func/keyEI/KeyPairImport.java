package func.keyEI;

import java.awt.BorderLayout;
import java.awt.Font;
import java.awt.GridLayout;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

import javax.swing.*;
import javax.swing.filechooser.FileNameExtensionFilter;

import util.MyKeyStore;

public class KeyPairImport extends JFrame {

	private JFrame rtnFrame, thisFrame;

	private JTextField filePath = new JTextField("..", 18);
	private JPasswordField password = new JPasswordField(17);
	private JButton buttonChooseFile = new JButton("Browse");
	private JButton buttonImport = new JButton("Import");

	private void setup() {

		setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
		filePath.setEditable(false);
		buttonImport.setEnabled(false);

		buttonChooseFile.addActionListener(new ActionListener() {
			@Override
			public void actionPerformed(ActionEvent e) {
				JFileChooser chooser = new JFileChooser();
				FileNameExtensionFilter filter = new FileNameExtensionFilter("PKCS #12", "p12");
				chooser.setFileFilter(filter);
				int returnVal = chooser.showSaveDialog(thisFrame);
				if (returnVal == JFileChooser.APPROVE_OPTION) {
					String path = chooser.getSelectedFile().getAbsolutePath();
					filePath.setText(path);
					buttonImport.setEnabled(true);

				}
			}
		});

		buttonImport.addActionListener(new ActionListener() {

			@Override
			public void actionPerformed(ActionEvent e) {

				try {
					FileInputStream fis = new FileInputStream(filePath.getText());
					
					KeyStore keyStore = KeyStore.getInstance("JKS");
					keyStore.load(fis, password.getPassword());
					
					fis.close();
					

					Enumeration<String>aliases = keyStore.aliases();
					String chosenAlias = aliases.nextElement();
					
					Key key = keyStore.getKey(chosenAlias, password.getPassword());
					Certificate[] chain = keyStore.getCertificateChain(chosenAlias);
					
					
					JPanel panel = new JPanel();
					JLabel label = new JLabel("Alias for imported key pair");
					JTextField alias = new JTextField (20);
					panel.add(label);
					panel.add(alias);
					String aliasString = null;
					
					while (true) {
						int option = JOptionPane.showOptionDialog(null, panel, "Alias for key pair",
								JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE, null, null, null);
						if (option == JOptionPane.OK_OPTION) {
							aliasString = alias.getText();
							if (aliasString.length() == 0)
								JOptionPane.showMessageDialog(null, "Password must contain at least 1 character");
							else
								break;
						} else if (option == JOptionPane.CANCEL_OPTION)
							return;
					}
					
					KeyStore ks = MyKeyStore.getInstance("keyPair");
					
					ks.setKeyEntry(aliasString, key, "password".toCharArray(), chain);
					MyKeyStore.save("keyPair");
					JOptionPane.showMessageDialog(null, "Imported Key Pair successfully stored in KeyStore under name : " + aliasString);

				} catch (FileNotFoundException ex) {
					JOptionPane.showMessageDialog(null, "File doesn't exist");
				} catch (IOException e1) {
					JOptionPane.showMessageDialog(null, "Wrong password");

				} catch (NoSuchAlgorithmException | CertificateException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (KeyStoreException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				} catch (UnrecoverableKeyException e1) {
					// TODO Auto-generated catch block
					e1.printStackTrace();
				}
			}
		});

		JButton buttonBack = new JButton ("Back");
		buttonBack.addActionListener(new ActionListener() {
			
			@Override
			public void actionPerformed(ActionEvent e) {
				thisFrame.dispose();
				rtnFrame.setVisible(true);
			}
		});
		
		
		JPanel panel = new JPanel(new GridLayout(0, 1));

		JPanel panel1 = new JPanel();
		panel1.add(buttonChooseFile);
		panel1.add(filePath);

		JPanel panel2 = new JPanel();
		JLabel label = new JLabel("Password");
		label.setFont(new Font(Font.SANS_SERIF, Font.BOLD, 14));
		panel2.add(label);
		panel2.add(password);

		panel.add(panel1);
		panel.add(panel2);
		
		JPanel buttonPanel = new JPanel();
		buttonPanel.add(buttonBack);
		buttonPanel.add(buttonImport);
		panel.add(buttonPanel);

		setContentPane(panel);

		pack();

	}

	public KeyPairImport(JFrame rtnFrame) {
		super("Key Pair Import");
		this.rtnFrame = rtnFrame;
		thisFrame = this;

		setup();

		rtnFrame.setVisible(false);
		this.setVisible(true);
	}
}
