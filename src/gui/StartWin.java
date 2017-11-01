package gui;

import javax.swing.*;

import func.*;
import func.keyEI.KeysImportExport;

import java.awt.*;
import java.awt.event.*;

public final class StartWin {
	
	static private JFrame frame;
	
	static private JButton btnGenerate;
	static private JButton btnKeysImportExport;
	static private JButton btnOverview;
	static private JButton btnSign;
	static private JButton btnExport;
	static private GridLayout layout;
	
	public static void start(){

		setup();
	}
	
	private StartWin() {

	}
	
	private static void setup(){
		
		layout = new GridLayout (5, 1);	
		frame = new JFrame("X.509");
		
		btnGenerate = new JButton("Generisanje novog para klju\u010Deva");
		btnKeysImportExport = new JButton("Izvoz/uvoz postoje\u010Beg para klju\u010Deva");
		btnOverview = new JButton("Pregled detalja postoje\u0107ih parova klju\u010Deva");
		btnSign = new JButton("Potpisivanje");
		btnExport = new JButton("Izvoz");
		
		addButtonListeners();
	
		frame.setLayout(layout);	
		frame.getContentPane().add(btnGenerate);		
		frame.getContentPane().add(btnKeysImportExport);		
		frame.getContentPane().add(btnOverview);		
		frame.getContentPane().add(btnSign);		
		frame.getContentPane().add(btnExport);
		
	
		frame.setSize(350,250);
	
		frame.addWindowListener(new WindowAdapter() {
			@Override
			public void windowClosing(WindowEvent e) {
				frame.dispose();				
			}			
		});
		
		frame.setVisible(true);
	}

	static private void addButtonListeners() {
		
		btnGenerate.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent e) {				
				new Generate();
			}
		});
		
		btnKeysImportExport.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent e) {
				KeysImportExport.start();			
				
			}
		});
		
		btnOverview.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent e) {
				new Overview();		
				
			}
		});
		
		btnSign.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent e) {
				new Sign();
				
				
			}
		});
		
		btnExport.addActionListener(new ActionListener() {			
			@Override
			public void actionPerformed(ActionEvent e) {
				new Export();				
				
			}
		});
		
		
	}

	public static JFrame getFrame() {
		return frame;
	}

	
}
