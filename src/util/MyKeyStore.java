package util;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

public class MyKeyStore {

	static private KeyStore keyPair = null;
	static private KeyStore certificate = null;

	static public KeyStore getInstance(String provider) throws KeyStoreException {
		switch (provider) {
		case "keyPair":
			if (keyPair == null)
				keyPair = load(provider);
			return keyPair;

		case "certificate":
			if (certificate == null)
				certificate = load(provider);
			return certificate;
		}
		return null;
	}

	static private KeyStore load(String provider) throws KeyStoreException {
		KeyStore keyStore = null;
		try {
			char[] password = "password".toCharArray();
			FileInputStream fis = new FileInputStream("store/"+provider+".jks");
			keyStore = KeyStore.getInstance("JKS");
			keyStore.load(fis, password);

			fis.close();

		} catch (FileNotFoundException e) {
			File theDir = new File("store");
			if (!theDir.exists()) {
			    System.out.println("creating directory: " );
			    boolean result = false;

			    try{
			        theDir.mkdir();
			        result = true;
			    } 
			    catch(SecurityException se){
			        //handle it
			    }        
			    if(result) {    
			        System.out.println("DIR created");  
			    }
			}
			e.printStackTrace();
			try {
				keyStore = KeyStore.getInstance("JKS");
				keyStore.load(null, null);

				char[] password = "password".toCharArray();

				FileOutputStream fos = new FileOutputStream("store/"+provider+".jks");
				keyStore.store(fos, password);
				fos.close();
			} catch (KeyStoreException | CertificateException | IOException | NoSuchAlgorithmException e1) {
				e1.printStackTrace();
			}
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return keyStore;
	}

	static KeyStore getKeyStore(String provider) {
		switch (provider) {
		case "keyPair":
			return keyPair;
		case "certificate":
			return certificate;
		}
		return null;
	}

	static void setToNull(String provider) {
		switch (provider) {
		case "keyPair":
			keyPair = null;
			return;
		case "certificate":
			certificate = null;
			return;
		}
	}

	static public void save(String provider) {
		KeyStore keyStore = getKeyStore(provider);

		if (keyStore != null) {
			try {
				char[] password = "password".toCharArray();
				FileOutputStream fos = new FileOutputStream("store/"+provider+".jks");
				keyStore.store(fos, password);
				fos.close();
			} catch (IOException | KeyStoreException | NoSuchAlgorithmException | CertificateException e) {
				e.printStackTrace();
			}
		}
		setToNull(provider);
	}
}
