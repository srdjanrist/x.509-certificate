

import java.security.Security;

import javax.swing.SwingUtilities;

import gui.*;

public class Main {

	public static void main(String[] args) {	
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
		SwingUtilities.invokeLater(new Runnable() {
            public void run() {
        		StartWin.start();
            }
        });
		
	}

}
