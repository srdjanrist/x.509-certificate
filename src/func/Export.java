package func;

import java.awt.*;
import java.awt.event.*;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.PrintWriter;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Enumeration;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;
import javax.swing.filechooser.FileNameExtensionFilter;

import org.bouncycastle.util.encoders.Base64;

import gui.*;
import util.MyKeyStore;

public class Export {

	private static Object[][] data;

	private static KeyStore certKeyStore = null;
	
	private static class Window extends JFrame {

		JButton buttonExport = new JButton("Export");
		
		private JTable generateTable() {
			Enumeration<String> aliases = null;
			try {

				certKeyStore = MyKeyStore.getInstance("certificate");

				aliases = certKeyStore.aliases();

			} catch (KeyStoreException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}

			String[] colNames = { "X509 Certificate Alias" };

			ArrayList<String> lista = new ArrayList();
			for (Enumeration<String> e = aliases; e != null && e.hasMoreElements();) {
				lista.add(e.nextElement());
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
						buttonExport.setEnabled(false);
					}
					buttonExport.setEnabled(true);
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

			buttonExport.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					exportCert(table.getSelectedRow());
				}

				
			});
			buttonExport.setEnabled(false);

			JPanel buttonPanel = new JPanel(new GridLayout(0, 2));
			buttonPanel.add(buttonBack);
			buttonPanel.add(buttonExport);

			panel.add(buttonPanel, BorderLayout.SOUTH);

			setSize(300, 200);
		}
		public Window() {
			super ("X509 Certificate Export");
			
			setup();
			
			/*JButton btnReturn = new JButton("Return");
			btnReturn.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent arg0) {
					dispose();
					StartWin.getFrame().setVisible(true);
				}
			});
			getContentPane().add(btnReturn, BorderLayout.NORTH);
			setSize(300, 200);*/
		}
	}
	
	private static String convertToPem(X509Certificate cert) throws CertificateEncodingException {
		 Base64 encoder = new Base64();
		 String cert_begin = "-----BEGIN CERTIFICATE-----\n";
		 String end_cert = "-----END CERTIFICATE-----";

		 byte[] derCert = cert.getEncoded();
		 String pemCertPre = new String(Base64.encode(derCert));
		 String pemCert = cert_begin + pemCertPre + end_cert;
		 return pemCert;
		}
	
	private static void exportCert(int selectedRow) {
		String alias = (String) data[selectedRow][0];
		X509Certificate cert;
		try {
			cert = (X509Certificate) certKeyStore.getCertificate(alias);
			JFileChooser chooser = new JFileChooser();
			FileNameExtensionFilter filter = new FileNameExtensionFilter("X.509", "cer");
			chooser.setFileFilter(filter);
			int returnVal = chooser.showSaveDialog(null);
			
			if (returnVal == JFileChooser.APPROVE_OPTION) {
				String path = chooser.getSelectedFile().getAbsolutePath();
				if (!path.endsWith(".cer"))
					path += ".cer";

				String encoded = convertToPem(cert);
				FileOutputStream fos = new FileOutputStream(path);
				PrintWriter pw = new PrintWriter(fos, true);
				pw.write(encoded);
				
				pw.close();
				fos.close();
				JOptionPane.showMessageDialog(null, "X.509 Certificate successfully exported to " + path);
				
			}else if (returnVal == JFileChooser.CANCEL_OPTION)
				return;
		} catch (KeyStoreException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateEncodingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (FileNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
		
	}
	public Export(){
		
		StartWin.getFrame().setVisible(false);
		
		new Window().setVisible(true);
	}
}
