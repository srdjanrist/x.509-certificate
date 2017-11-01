package func.keyEI;

import java.awt.*;
import java.awt.event.*;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Enumeration;

import javax.swing.*;
import javax.swing.event.ListSelectionEvent;
import javax.swing.event.ListSelectionListener;

import gui.*;

public class KeysImportExport {

	private static Window win = new Window();

	private static class Window extends JFrame {

		private void setup() {

			setDefaultCloseOperation(WindowConstants.EXIT_ON_CLOSE);
			
			JButton buttonExport = new JButton("Export");
			buttonExport.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					new KeyPairExport(win);					
				}
			});

			JButton buttonImport = new JButton("Import");
			buttonImport.addActionListener(new ActionListener() {

				@Override
				public void actionPerformed(ActionEvent e) {
					new KeyPairImport(win);
				}
			});

			JButton buttonReturn = new JButton("Back");
			buttonReturn.addActionListener(new ActionListener() {
				public void actionPerformed(ActionEvent arg0) {
					dispose();
					StartWin.getFrame().setVisible(true);
				}
			});

			getContentPane().add(buttonExport, BorderLayout.WEST);
			getContentPane().add(buttonImport, BorderLayout.EAST);
			getContentPane().add(buttonReturn, BorderLayout.SOUTH);
			pack();
		}

		public Window() {
			super("Key pair import/export");
			setup();
		}

	}

	public static void start() {
		StartWin.getFrame().setVisible(false);

		win.setVisible(true);
		
	}
}
