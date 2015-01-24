import java.awt.BorderLayout;
import java.awt.event.*;
import java.io.File;

import javax.swing.*;


public class GUIXMLDigitalSignature extends JFrame implements WindowListener,ActionListener{
	private JPanel panel;
	private JPanel panelEnveloping;
	private JPanel panelEnveloped;
	private JPanel panelDetached;
	final JFileChooser fc = new JFileChooser();
	private File file;
	

	public GUIXMLDigitalSignature() {
		//Call JFrame constructor
		super ("XML Digital Signature");
		addWindowListener(this);
		setDefaultCloseOperation(JFrame.EXIT_ON_CLOSE);
		setSize(400, 600);
		
		panelEnveloping = new JPanel();
		panelEnveloped = new JPanel();
		panelDetached = new JPanel();
		
		panel = new JPanel();
		add(panel, BorderLayout.CENTER);
		panel.setLayout(null);
		
		JLabel label1= new JLabel("Choose a signature type: ");
		panel.add(label1);
		label1.setBounds(20, 5, 200, 20);
		
		JButton btnenv = new JButton("Enveloped");
		btnenv.setBounds(50,70,150,30);
		panel.add(btnenv);
		btnenv.addActionListener(this);
		btnenv.setActionCommand("getEnveloped");
		
		JButton btnenving = new JButton("Enveloping");
		btnenving.setBounds(50,110,150,30);
		panel.add(btnenving);
		btnenving.addActionListener(this);
		btnenving.setActionCommand("getEnveloping");
		
		JButton btndet = new JButton("Detached");
		btndet.setBounds(50,150,150,30);
		panel.add(btndet);
		btndet.addActionListener(this);
		btndet.setActionCommand("getDetached");
		
		
		setVisible(true);
	}
	
	
	public void defautGUI(){
		if(panelEnveloping.isVisible()) panelEnveloping.setVisible(false);
		if(panelDetached.isVisible()) panelDetached.setVisible(false);
		if(panelEnveloped.isVisible()) panelEnveloped.setVisible(false);
		
		panel.setVisible(true);
		
	}
	
	public void EnvelopedGUI(){
		if(panel.isVisible()) panel.setVisible(false);
		if(panelEnveloping.isVisible()) panelEnveloping.setVisible(false);
		if(panelDetached.isVisible()) panelDetached.setVisible(false);
		
		panelEnveloped = new JPanel();
		add(panelEnveloped, BorderLayout.CENTER);
		
		JLabel label1= new JLabel("Enveloped");
		panelEnveloped.add(label1);
		label1.setBounds(20, 5, 200, 20);
		
		//Static type signature enveloped
		
		//new xmlsignatureoptionselector
		//URI
		//pub
		JButton opkf = new JButton("Open Public Key file");
		opkf.setBounds(50, 100, 30, 30);
		panelEnveloped.add(opkf);
		opkf.addActionListener(this);
		opkf.setActionCommand("openbubkey");
		//priv
		//alg/dig
		
		
		
		
		JButton back = new JButton("Back");
		back.setBounds(50, 200, 100, 30);
		panelEnveloped.add(back);
		back.addActionListener(this);
		back.setActionCommand("back");
		
		panelEnveloped.setVisible(true);
		
	}
	
	public void DetachedGUI(){
		if(panel.isVisible())	panel.setVisible(false);
		
		panelDetached = new JPanel();
		add(panelDetached, BorderLayout.CENTER);
		
		JLabel label1 = new JLabel("Detached");
		panelDetached.add(label1);
		label1.setBounds(20, 5, 200, 20);
		
		JButton back = new JButton("Back");
		back.setBounds(50, 200, 100, 30);
		panelDetached.add(back);
		back.addActionListener(this);
		back.setActionCommand("back");
		
		panelDetached.setVisible(true);
	}
	
	public void EnvelopingGUI(){
		if(panel.isVisible())	panel.setVisible(false);
		if(panelEnveloped.isVisible()) panelEnveloped.setVisible(false);
		if(panelDetached.isVisible()) panelDetached.setVisible(false);
		
		
		panelEnveloping = new JPanel();
		add(panelEnveloping, BorderLayout.CENTER);
		
		JLabel label1 = new JLabel("Enveloping");
		panelEnveloping.add(label1);
		label1.setBounds(20, 5, 200, 20);
		
		JButton back = new JButton("Back");
		back.setBounds(50, 200, 100, 30);
		panelEnveloping.add(back);
		back.addActionListener(this);
		back.setActionCommand("back");
		
		panelEnveloping.setVisible(true);
	}
	
	public void actionPerformed(ActionEvent e){
		if("getEnveloped".equals(e.getActionCommand())){	this.EnvelopedGUI();}
		if("getEnveloping".equals(e.getActionCommand())){ 	this.EnvelopingGUI();}
		if("getDetached".equals(e.getActionCommand())){ 	this.DetachedGUI();}
		if("back".equals(e.getActionCommand())){	this.defautGUI();}
		
		//open pub key file
		if("openpubkey".equals(e.getActionCommand())){
			int returnVal = fc.showOpenDialog(this);
			if(returnVal == JFileChooser.APPROVE_OPTION){
				file = fc.getSelectedFile();
			}else {
				System.out.println("File not valid");
			}
		}
	}

	@Override
	public void windowActivated(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void windowClosed(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void windowClosing(WindowEvent e) {
		// TODO Auto-generated method stub
		dispose();
		System.exit(0);
	}

	@Override
	public void windowDeactivated(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void windowDeiconified(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void windowIconified(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}

	@Override
	public void windowOpened(WindowEvent e) {
		// TODO Auto-generated method stub
		
	}
}
