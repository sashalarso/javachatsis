package client;

import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;

import java.io.*;
import java.net.Socket;
import java.util.Arrays;
import java.util.Locale;
import java.util.Scanner;

import java.io.IOException;
import sun.misc.BASE64Encoder;
import sun.misc.BASE64Decoder;


public class TheClient extends Thread {

	private  boolean JAVACARDMODE = true;
	private boolean HEAVYCLIENT = true;
    private PassThruCardService servClient = null;
    boolean DISPLAY = true;

	private Socket socket;

	private Scanner inConsole, inNetwork;
	private PrintWriter outConsole, outNetwork;

	
	private static final int MSG = 0;
	private static final int SENDFILE = 1; 
	private static final int LOGOUT = 2; 
	private static final int LIST = 15;
	private static final int PRIVMSG = 16;
	private static final int BROADCAST = 17;
	private static final int HELP = 18;
	private static final int TEST = 19;

	private static final int CONNECTED = 3;
	private static final int ALREADYCONNECTED = 4;
	private static final int REGISTERED = 5;
	private static final int ERR_REGISTERED = 6;
	private static final int DISCONNECTED = 7;
	private static final int SENDFILESTOP = 9;
	private static final int FILETRANSFERMODEON = 10;
	private static final int FILETRANSFERMODEOFF = 11;
	private static final int ISUSERCONNECTED = 12;
	private static final int RECEIVERISCONNECTED = 13;
	private static final int RECEIVERISNOTCONNECTED = 14;
	private static final int MESSAGE=15;

	private boolean isClientConnected = false;

	private boolean fileTransferMode = false;
	private boolean isReceiverConnected = false;
	private boolean checkReceiverState = false;

	private FileOutputStream fout = null;
	private static final int DMS_SENDFILE = 100000;

	private static final byte CLA = (byte) 0x90;
	private static final byte P1 = (byte) 0x00;
	private static final byte P2 = (byte) 0x00;
	private final static byte INS_GET_PUBLIC_RSA_KEY = (byte)0xFE;
	private final static byte INS_GENERATE_RSA_KEY = (byte)0xF6;
	private static final byte INS_RSA_ENCRYPT = (byte) 0xA0;
	private static final byte INS_RSA_DECRYPT = (byte) 0xA2;

	private static short DMS_DES = 248; // DATA MAX SIZE for DES
    private static final byte INS_DES_DECRYPT = (byte) 0xB0;
    private static final byte INS_DES_ENCRYPT = (byte) 0xB2;

    public TheClient(String host, int port) throws IOException {
		initStream(host, port);
		chooseClient();
		if (JAVACARDMODE && HEAVYCLIENT){
			cardAuthentication();
			
		}
		else{
			authentication();
		}
		start();
		listenConsole();
    }
	public void chooseClient(){
		Scanner scanner = new Scanner(System.in);

        System.out.println("Veuillez appuyer sur Entrée : ");
        String userInput = scanner.nextLine();

        if (userInput.equals("1")) {
            System.out.println("Client lourd");
			HEAVYCLIENT=true;
			sendServer("1");
        } else {
            System.out.println("Vous n'avez pas appuyé sur Entrée.");
			HEAVYCLIENT=false;
			this.JAVACARDMODE=false;
			sendServer("2");

        }

        
	}

    private ResponseAPDU sendAPDU(CommandAPDU cmd) {
	    return sendAPDU(cmd, true);
    }

	private ResponseAPDU sendAPDU(CommandAPDU cmd, boolean display) {
		ResponseAPDU result = null;
		try {
			result = this.servClient.sendCommandAPDU(cmd);
			if (display)
				displayAPDU(cmd, result);
		} catch (Exception e) {
			System.out.println("Exception caught in sendAPDU: " + e.getMessage());
			java.lang.System.exit(-1);
		}
		return result;
	}


    /************************************************
     * *********** BEGINNING OF TOOLS ***************
     * **********************************************/


    private String apdu2string( APDU apdu ) {
	    return removeCR( HexString.hexify( apdu.getBytes() ) );
    }


    public void displayAPDU( APDU apdu ) {
	System.out.println( removeCR( HexString.hexify( apdu.getBytes() ) ) + "\n" );
    }


    public void displayAPDU( CommandAPDU termCmd, ResponseAPDU cardResp ) {
	System.out.println( "--> Term: " + removeCR( HexString.hexify( termCmd.getBytes() ) ) );
	System.out.println( "<-- Card: " + removeCR( HexString.hexify( cardResp.getBytes() ) ) );
    }


    private String removeCR( String string ) {
	    return string.replace( '\n', ' ' );
    }

	
    /******************************************
     * *********** END OF TOOLS ***************
     * ****************************************/


    private boolean selectApplet() {
	 boolean cardOk = false;
	 try {
	    CommandAPDU cmd = new CommandAPDU( new byte[] {
                (byte)0x00, (byte)0xA4, (byte)0x04, (byte)0x00, (byte)0x0A,
		(byte)0xA0, (byte)0x00, (byte)0x00, (byte)0x00, (byte)0x62, 
		(byte)0x03, (byte)0x01, (byte)0x0C, (byte)0x06, (byte)0x01
            } );
            ResponseAPDU resp = this.sendAPDU( cmd );
	    if( this.apdu2string( resp ).equals( "90 00" ) )
		    cardOk = true;
	 } catch(Exception e) {
            System.out.println( "Exception caught in selectApplet: " + e.getMessage() );
            java.lang.System.exit( -1 );
        }
	return cardOk;
    }
	
	public void initStream(String host, int port) throws IOException {
		this.inConsole = new Scanner(System.in);
		this.outConsole = new PrintWriter(System.out);

		try {
			this.socket = new Socket(host, port);
			this.inNetwork = new Scanner(socket.getInputStream());
			this.outNetwork = new PrintWriter(socket.getOutputStream(), true);
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

	private void closeNetwork() throws IOException {
		this.outNetwork.close();
		this.socket.close();
		System.exit(0);
	}

	private void closeConsole() throws IOException {
		this.outConsole.close();
	}
		
	private void printScreen(String raw) {
		this.outConsole.println(raw);
		this.outConsole.flush();
	}

	private void sendServer(String raw) {
		this.outNetwork.println(raw);
		this.outNetwork.flush();
	}

	private void sendMessage(String raw) {
		String clienttype;
		if(this.JAVACARDMODE){
			clienttype="heavy";
		}
		else{
			clienttype="light";
		}
		this.outNetwork.println(raw);
		this.outNetwork.flush();
	}

	private static byte[] shortToByteArray(short s) {
		return new byte[] { (byte) ((s & (short) 0xff00) >> 8), (byte) (s & (short) 0x00ff) };
	}

	private String toLowerCases(String s) {
		String r = "";
		for(char c: s.toCharArray()) {
			r += Character.toLowerCase(c);
		}
		return r;
	}

	private void displayBytes(byte[] bytes){
		int i = 0;
		for (byte b : bytes) {
			System.out.printf("%02X ", b);
			if (++i%8 == 0)
				System.out.println("");
		}
	}
	//du projet java card précédent
	private static short byteToShort(byte b) {
		return (short) (b & 0xff);
	}

	private static short byteArrayToShort(byte[] ba, short offset) {
		return (short) (((ba[offset] << 8)) | ((ba[(short) (offset + 1)] & 0xff)));
	}

	private static byte[] addPadding(byte[] data, long fileLength) {
		short paddingSize = (short) (8 - (fileLength % 8));
		byte[] paddingData = new byte[(short) (data.length + paddingSize)];

		System.arraycopy(data, 0, paddingData, 0, (short) data.length);
		for (short i = (short) data.length; i < (data.length + paddingSize); ++i)
			paddingData[i] = shortToByteArray(paddingSize)[1];

		return paddingData;
	}

	private static byte[] removePadding(byte[] paddingData) {
		short paddingSize = byteToShort(paddingData[paddingData.length - 1]);
		if (paddingSize > 8)
			return paddingData;
		
		for (short i = (short) (paddingData.length - paddingSize); i < paddingData.length; ++i)
			if (paddingData[i] != (byte) paddingSize)
				return paddingData;

		short dataLength = (short) (paddingData.length - paddingSize);
		byte[] data = new byte[dataLength];
		System.arraycopy(paddingData, 0, data, 0, (short) dataLength);

		return data;
	}

	/*********/

	private boolean isUserconnected(String raw){
		String[] splitRaw = raw.split(" ");
		if (splitRaw.length == 3) {
			sendServer("<SYSTEM> [SENDFILE]: " + "ISUSERCONNECTED" + " " + splitRaw[1].trim() + " " + splitRaw[2].trim());
			return true;
		}else {
			printScreen("<SYSTEM> [SENDFILE]: Bad arguments");
			return false;
		}
	}

	private void sendFile(String raw) throws IOException {
		if(!checkReceiverState){
			this.checkReceiverState = isUserconnected(raw);
		} else {
			if (this.isReceiverConnected) {
				String[] splitRaw = raw.split(" ");
				if (splitRaw.length == 8) {
					File f = new File("../out/secureApp/client/Files/" + splitRaw[7].trim());
					if (!f.exists()) {
						printScreen("<SYSTEM> [SENDFILE]: File doesn't exist");
					} else {
						printScreen(splitRaw[0] + " " + splitRaw[1] +" "+splitRaw[2] + " " + splitRaw[3] +" "+splitRaw[4] + " " + splitRaw[5] +" "+splitRaw[6]+" "+splitRaw[7]);
						sendServer("/sendfile " + splitRaw[5] + " " + splitRaw[7]);
						FileInputStream fin = new FileInputStream(f);
						int by = 0; int i = 0;
						StringBuilder sb = new StringBuilder();
						
						while (by != -1) {
							by = fin.read(); ++i;
							sb.append(String.valueOf(by)+";");

							if (by != -1 && i == DMS_SENDFILE) {
								sendServer("<SYSTEM> [SENDFILE] " + sb.toString());
								i = 0;
								sb = new StringBuilder();
							}
							else if (by == -1 && i > 1)
								sendServer("<SYSTEM> [SENDFILE] " + sb.toString());		
						}
						
						sendServer("<SYSTEM> [SENDFILE]: " + "SENDFILESTOP");
					}

					this.checkReceiverState = false;
					this.isReceiverConnected = false;
				} else
					printScreen("<SYSTEM> [SENDFILE]: Bad arguments");
			}
		}
	}
	private void sendCryptedFile(String raw) throws IOException {
		
		if(!checkReceiverState){
			this.checkReceiverState = isUserconnected(raw);
			
		} else {
			if (this.isReceiverConnected) {
				String[] splitRaw = raw.split(" ");
				
				if (splitRaw.length == 8) {
					File f = new File("../out/secureApp/client/Files/" + splitRaw[7].trim());
					
					if (!f.exists()) {
						printScreen("<SYSTEM> [SENDFILE]: File doesn't exist");
					} else {
						printScreen(splitRaw[0] + " " + splitRaw[1] +" "+splitRaw[2] + " " + splitRaw[3] +" "+splitRaw[4] + " " + splitRaw[5] +" "+splitRaw[6]+" "+splitRaw[7]);
						sendServer("/sendfile " + splitRaw[5] + " " + splitRaw[7]);
						FileInputStream fin = new FileInputStream(f);
						int by = 0; int i = 0;
						StringBuilder sb = new StringBuilder();
						
						while (by != -1) {
							
							by = fin.read(); ++i;
							if(by!=-1){
								sb.append((char)by);
								
							}
							
							
							else if (by == -1 && i > 1){
								
								//printScreen(sb.toString());
								sendServer("<SYSTEM> [SENDFILE] " + cipherMessage(sb.toString())+" heavy" );	
							}
									
						}
						
						sendServer("<SYSTEM> [SENDFILE]: " + "SENDFILESTOP");
					}

					this.checkReceiverState = false;
					this.isReceiverConnected = false;
				} else
					printScreen("<SYSTEM> [SENDFILE]: Bad arguments");
			}
		}
	}

	private synchronized void getFile(String raw) throws IOException {
		String name="";
		if(raw.startsWith("<SYSTEM> [SENDFILE]: SENDFILESTART")){
			String[] splitRaw = raw.split(" ");
			name=splitRaw[4];
			this.fout = new FileOutputStream("../out/secureApp/client/Files/retrieved_" + splitRaw[4]);
		} else if (raw.startsWith("<SYSTEM> [SENDFILE]: SENDFILESTOP")) {
			this.fileTransferMode = false;
			this.fout.close();
			
		} else {
			if (raw.startsWith("<SYSTEM> [SENDFILE]")) {
				//printScreen(raw);
				//printScreen("test2");
				if(!raw.endsWith("heavy")){
					//printScreen(raw);
				String[] byteValue = raw.split(" ")[2].split(";");
				for (int i = 0; i < byteValue.length -1; ++i)
					this.fout.write(Byte.parseByte(String.valueOf(shortToByteArray(Short.parseShort(byteValue[i]))[1]), 10));
				printScreen("<SYSTEM> FILE RECEIVED " +"retrieved_"+name);
				}
				else if(raw.endsWith("heavy")&&!JAVACARDMODE){
					//printScreen(raw);
					//printScreen("test1");
				String[] byteValue = raw.split(" ");
				//printScreen("a dechiffrer "+byteValue[2]);

				
				byte[] result=byteValue[2].getBytes();
				//printScreen(result.toString());
				this.fout.write(result);
				
				printScreen("<SYSTEM> FILE RECEIVED " +"retrieved_heavy"+name);
				}
				else if(raw.endsWith("heavy")&&JAVACARDMODE){
					//printScreen(raw);
					//printScreen("test1");
				String[] byteValue = raw.split(" ");
				//printScreen("a dechiffrer "+byteValue[2]);

				String unciphered=uncipherMessage(byteValue[2]);
				byte[] result=unciphered.getBytes();
				//printScreen(result.toString());
				this.fout.write(result);
				
				printScreen("<SYSTEM> FILE RECEIVED " +"retrieved_heavy"+name);
				}
				
			} else
				printScreen(raw);
		}
	}

	private void logout() {
		sendServer("/logout");
	}

	private void authentication() throws IOException {
		while(this.inNetwork.hasNextLine()) {
			String raw = this.inNetwork.nextLine().trim();
			printScreen(raw);
			
			if (raw.startsWith("<SYSTEM> Enter your username") || raw.startsWith("Enter password:") || raw.startsWith("Confirm password:")){
				sendServer(this.inConsole.nextLine().trim());
			} else if(raw.startsWith("<SYSTEM> Connected as:")){
				this.isClientConnected = true;
				return;
			} else if (raw.startsWith("<SYSTEM> User connected limit reached") || raw.startsWith("<SYSTEM> Registration Successful") || raw.startsWith("<SYSTEM> Username or password is incorrect") || raw.startsWith("<SYSTEM> User already connected")){
				closeConsole();
				closeNetwork();
				return;
			}
		}
	}

	private boolean initNewCard(SmartCard card) {
		if( card != null )
			System.out.println("Smartcard inserted\n");
		else {
			System.out.println("Did not get a smartcard");
			return false;
		}
		System.out.println("ATR: " + HexString.hexify( card.getCardID().getATR() ) + "\n");
	
		try {
			this.servClient = (PassThruCardService)card.getCardService( PassThruCardService.class, true);
		} catch(Exception e) {
			System.out.println(e.getMessage());
			return false;
		}
	
		System.out.println("Applet selecting...");
		if(!this.selectApplet()) {
			System.out.println("Wrong card, no applet to select!\n");
			System.exit( 1 );
			return false;
		} else {
			System.out.println("Applet selected\n");
			return true;
		}
	}

	private byte[] sendAndRetrieveChallengeApplet(byte[] challengeBytes) {
		CommandAPDU cmd;
		ResponseAPDU resp;

		int LC = challengeBytes.length;
		byte[] DATA = challengeBytes;

		byte[] cmd_b = new byte[LC + 6];
		cmd_b[0] = CLA;
		cmd_b[1] = INS_RSA_DECRYPT;
		cmd_b[2] = (byte)0xFF;
		cmd_b[3] = P2;
		cmd_b[4] = (byte) LC;
		System.arraycopy(DATA, 0, cmd_b, 5, LC);
		cmd_b[cmd_b.length - 1] = (byte) LC;

		cmd = new CommandAPDU(cmd_b);
		resp = this.sendAPDU(cmd, DISPLAY);

		
		byte[] bytes = resp.getBytes();
		byte[] data = new byte[bytes.length - 2];
		System.arraycopy(bytes, 0, data, 0, bytes.length - 2);
		return data;
		
	}

	private String getKeyElementFromApplet(byte b) {
		CommandAPDU cmd;
		ResponseAPDU resp;

		byte[] cmd_b = new byte[5];
		cmd_b[0] = CLA;
		cmd_b[1] = INS_GET_PUBLIC_RSA_KEY;
		cmd_b[2] = P1;
		cmd_b[3] = b;
		cmd_b[4] = (byte) 0x00;

		cmd = new CommandAPDU(cmd_b);
		resp = this.sendAPDU(cmd, DISPLAY);
		
		byte[] bytes = resp.getBytes();
		byte[] data = new byte[bytes.length - 3];
		System.arraycopy(bytes, 1, data, 0, bytes.length - 3);
	
		displayBytes(data);

		BASE64Encoder encoder = new BASE64Encoder();
		return encoder.encode(data).trim().replaceAll("\n", "").replaceAll("\r", "");
		 
	}

	private void generateRSAKeysFromApplet() {
		CommandAPDU cmd;
		ResponseAPDU resp;

		byte[] cmd_b = new byte[5];
		cmd_b[0] = CLA;
		cmd_b[1] = INS_GENERATE_RSA_KEY;
		cmd_b[2] = P1;
		cmd_b[3] = P2;
		cmd_b[4] = (byte) 0x00;

		cmd = new CommandAPDU(cmd_b);
		resp = this.sendAPDU(cmd, DISPLAY);

		
		System.out.println("GENERATE RSA KEY Error");
		
	}

	private void cardAuthentication() throws IOException {
		while(this.inNetwork.hasNextLine()) {
			String raw = this.inNetwork.nextLine().trim();
			
			if (!raw.startsWith("<SYSTEM> AUTHENTICATION NEW") && !raw.startsWith("<SYSTEM> REGISTRATION NEW"))
				printScreen(raw);
			
			if (raw.startsWith("<SYSTEM> Enter your username")) {
				sendServer(this.inConsole.nextLine().trim());
			} else if (raw.startsWith("<SYSTEM> REGISTRATION NEW")) {
				try {
					SmartCard.start();
					System.out.print("Smartcard inserted?... "); 
					CardRequest cr = new CardRequest (CardRequest.ANYCARD, null, null); 
					SmartCard sm = SmartCard.waitForCard (cr);
				    
					if (sm != null) {
						System.out.println ("Got a SmartCard object!\n");
					} else
						System.out.println("Did not get a SmartCard object!\n");
				   
					if(this.initNewCard(sm)) {
						generateRSAKeysFromApplet();
						String modulus = getKeyElementFromApplet((byte) 0x00);
						String exponent = getKeyElementFromApplet((byte) 0x01);
						sendServer("<SYSTEM> REGISTRATION MODULUS " + modulus);
						sendServer("<SYSTEM> REGISTRATION EXPONENT " + exponent);
					}
				} catch( Exception e ) {
					
					SmartCard.shutdown();
					closeConsole();
					closeNetwork();
				}

			} else if (raw.startsWith("<SYSTEM> AUTHENTICATION NEW")) {
				String challengeBytesB64 = raw.split(" ")[3];
				BASE64Decoder decoder = new BASE64Decoder();
				byte[] challengeBytes = decoder.decodeBuffer(challengeBytesB64);

				try {
					SmartCard.start();
					System.out.print("Smartcard inserted?... "); 
					CardRequest cr = new CardRequest (CardRequest.ANYCARD, null, null); 
					SmartCard sm = SmartCard.waitForCard (cr);
				    
					if (sm != null) {
						System.out.println ("Got a SmartCard object!\n");
					} else
						System.out.println("Did not get a SmartCard object!\n");
				   
					if(this.initNewCard(sm)) {
						try {
							BASE64Encoder encoder = new BASE64Encoder();
							String challengeBytesUncipheredB64 = encoder.encode(sendAndRetrieveChallengeApplet(challengeBytes)).trim().replaceAll("\n", "").replaceAll("\r", "");
							sendServer("<SYSTEM> AUTHENTICATION SOLVED " + challengeBytesUncipheredB64);
						} catch(Exception e) {
							System.out.println(e);
						}
					}
				} catch( Exception e ) {
					System.out.println("TheClient error: " + e.getMessage());
					SmartCard.shutdown();
					closeConsole();
					closeNetwork();
				}

			} else if(raw.startsWith("<SYSTEM> Connected as:")) {
				this.isClientConnected = true;
				return;
			} else if (raw.startsWith("<SYSTEM> Authentication error") || raw.startsWith("<SYSTEM> Registration Successful") || raw.startsWith("<SYSTEM> User connected limit reached") || raw.startsWith("<SYSTEM> Username is not registered") || raw.startsWith("<SYSTEM> User already connected")){
				SmartCard.shutdown();
				closeConsole();
				closeNetwork();
				return;
			}
		}
	}

	private synchronized String cipherMessage(String raw) {
		CommandAPDU cmd;
		ResponseAPDU resp;

		byte[] bytes = raw.getBytes();
		int remainingBytes = bytes.length;
		byte[] res = new byte[remainingBytes + (short) (8 - (raw.getBytes().length % 8))];

		short i = 0;
		while (remainingBytes > DMS_DES) {
			byte[] data = new byte[DMS_DES];
			System.arraycopy(bytes, i * DMS_DES, data, 0, DMS_DES);

			byte[] payload = new byte[DMS_DES + 6];
			payload[0] = CLA;
			payload[1] = INS_DES_ENCRYPT;
			payload[2] = P1;
			payload[3] = P2;
			payload[4] = (byte) DMS_DES;
			System.arraycopy(data, 0, payload, 5, DMS_DES);
			payload[payload.length - 1] = (byte) DMS_DES;
			
			cmd = new CommandAPDU(payload);
			resp = this.sendAPDU(cmd, DISPLAY);

			
			byte[] b = resp.getBytes();
			System.arraycopy(b, 0, res, i * DMS_DES, b.length - 2);
			++i; remainingBytes -= DMS_DES;
			
		}

		byte[] data = new byte[remainingBytes];
		System.arraycopy(bytes, i * DMS_DES, data, 0, remainingBytes);
		data = addPadding(data, raw.getBytes().length);

		byte[] payload = new byte[data.length + 6];
		payload[0] = CLA;
		payload[1] = INS_DES_ENCRYPT;
		payload[2] = P1;
		payload[3] = P2;
		payload[4] = (byte) data.length;
		System.arraycopy(data, 0, payload, 5, data.length);
		payload[payload.length - 1] = (byte) data.length;
		
		cmd = new CommandAPDU(payload);
		resp = this.sendAPDU(cmd, DISPLAY);

		
		byte[] b = resp.getBytes();
		System.arraycopy(b, 0, res, i * DMS_DES, b.length - 2);
		BASE64Encoder encoder = new BASE64Encoder();
		return encoder.encode(res).trim().replaceAll("\n", "").replaceAll("\r", "");
		
	}

	private synchronized String encryptBlock(String raw) {
		CommandAPDU cmd;
		ResponseAPDU resp;
		byte[] bytes = raw.getBytes();
		
		if(raw.getBytes().length<DMS_DES && raw.getBytes().length%8!=0){
			bytes=addPadding(raw.getBytes(), raw.getBytes().length);
			
		}
		
		byte[] res = new byte[bytes.length];

	
		byte[] data = new byte[bytes.length];
		System.arraycopy(bytes,0, data, 0,bytes.length);
		
		byte[] payload = new byte[bytes.length + 6];
		payload[0] = CLA;
		payload[1] = INS_DES_ENCRYPT;
		payload[2] = P1;
		payload[3] = P2;
		payload[4] = (byte) bytes.length;
		System.arraycopy(data, 0, payload, 5, bytes.length);
		payload[payload.length - 1] = (byte) bytes.length;
		
		cmd = new CommandAPDU(payload);
		resp = this.sendAPDU(cmd, DISPLAY);

		byte[] b = resp.getBytes();
		System.arraycopy(b, 0, res,0, b.length - 2);	
	
		
		
		BASE64Encoder encoder = new BASE64Encoder();
		return encoder.encode(res).trim().replaceAll("\n", "").replaceAll("\r", "");
		
		
	}
	
	private synchronized String uncipherMessage(String raw) throws IOException {
		CommandAPDU cmd;
		ResponseAPDU resp;

		BASE64Decoder decoder = new BASE64Decoder();
		String[] splitRaw = raw.split(" ");
		byte[] bytes = decoder.decodeBuffer(raw);
		int remainingBytes = bytes.length;

		byte[] res = new byte[remainingBytes];

		short i = 0;
		while (remainingBytes > DMS_DES) {
			byte[] data = new byte[DMS_DES];
			System.arraycopy(bytes, i * DMS_DES, data, 0, DMS_DES);

			byte[] payload = new byte[DMS_DES + 6];
			payload[0] = CLA;
			payload[1] = INS_DES_DECRYPT;
			payload[2] = P1;
			payload[3] = P2;
			payload[4] = (byte) DMS_DES;
			System.arraycopy(data, 0, payload, 5, DMS_DES);
			payload[payload.length - 1] = (byte) DMS_DES;
			
			cmd = new CommandAPDU(payload);
			resp = this.sendAPDU(cmd, DISPLAY);

			
			byte[] b = resp.getBytes();
			System.arraycopy(b, 0, res, i * DMS_DES, b.length - 2);
			++i; remainingBytes -= DMS_DES;
			
		}
		printScreen("remaining bytes : "+remainingBytes);
		byte[] data = new byte[remainingBytes];
		System.arraycopy(bytes, i * DMS_DES, data, 0, remainingBytes);

		byte[] payload = new byte[data.length + 6];
		payload[0] = CLA;
		payload[1] = INS_DES_DECRYPT;
		payload[2] = P1;
		payload[3] = P2;
		payload[4] = (byte) data.length;
		System.arraycopy(data, 0, payload, 5, data.length);
		payload[payload.length - 1] = (byte) data.length;
		
		cmd = new CommandAPDU(payload);
		
		resp = this.sendAPDU(cmd, DISPLAY);
		
		
		byte[] b = resp.getBytes();
		System.arraycopy(b, 0, res, i * DMS_DES, b.length - 2);
		return new String(removePadding(res));
		
	}

	private synchronized void displayHelp(){
		printScreen("Useful commands:");
		printScreen("/list : list connected users");
		printScreen("/msg destination message : send private message");
		printScreen("/sendfile destination file :sendfile to user");
		printScreen("/exit : leave the chat");
		printScreen("/broadcast message : broadcast message to all connected users");


	}

	/*********/

	private int parseNetwork(String text){
		
		if(text.startsWith("<SYSTEM> Disconnecting..."))
			return DISCONNECTED;
		else if(text.startsWith("<SYSTEM> [SENDFILE]: SENDFILESTART"))
			return FILETRANSFERMODEON;
		else if(text.startsWith("<SYSTEM> [SENDFILE]: SENDFILESTOP"))
			return FILETRANSFERMODEOFF;
		else if(text.startsWith("<SYSTEM> [SENDFILE]: User is connected")) 
			return RECEIVERISCONNECTED;
		else if(text.startsWith("<SYSTEM> [SENDFILE]: User is not connected")) 
			return RECEIVERISNOTCONNECTED;
		else if(text.startsWith("[From")) 
			return MESSAGE;
		else if(text.startsWith("BROADCAST")) 
			return BROADCAST;
		else
			return MSG;
	}

	private void listenNetwork() throws IOException {
		while(this.inNetwork.hasNextLine()) {
			String raw = this.inNetwork.nextLine().trim();
			
			switch (parseNetwork(raw)) {
				case FILETRANSFERMODEON:
					this.fileTransferMode = true;
					break;
				case RECEIVERISCONNECTED:
					this.isReceiverConnected = true;
					if(JAVACARDMODE){
						sendCryptedFile(raw);
					}
					else{
						sendFile(raw);
					}
					
					break;
				case RECEIVERISNOTCONNECTED:
					this.isReceiverConnected = false;
					this.checkReceiverState = false;
					break;
				case DISCONNECTED:
					SmartCard.shutdown();
					closeConsole();
					closeNetwork();
					break;
				case MESSAGE:
					String[] parts=raw.split(" ");
					if(parts.length==4 && parts[3].equals("heavy") && JAVACARDMODE){
						raw=uncipherMessage(parts[2]);
						printScreen(raw);
					}
					else if(parts.length==4 && parts[3].equals("light") ){
						printScreen(parts[0] + " " + parts[1] + " " + parts[2]);
					}
					else if(parts.length==4 && parts[3].equals("heavy") && !JAVACARDMODE ){
						printScreen(parts[0] + " " + parts[1] + " " + parts[2]);
					}
					else if(parts.length==3){
						printScreen(parts[0] + " " + parts[1] + " " + parts[2]);
					}
					break;
				case BROADCAST:
					
					String[] newparts=raw.split(" ");
					if(JAVACARDMODE && newparts.length>3 && newparts[3].equals("heavy")){
						printScreen(newparts[1] + " " + uncipherMessage(newparts[2]));
					}
					else if(newparts.length>3 && newparts[3].equals("light")){
						printScreen(newparts[1] + " " + newparts[2]);
					}
					else if(newparts.length>3 && newparts[3].equals("heavy") && !JAVACARDMODE){
						printScreen(newparts[1] + " " + newparts[2]);
					}
					else if(newparts.length==3){
						printScreen(newparts[1] + " " + newparts[2]);
					}
					else{
						printScreen(raw);
					}
					break;	
				default:
					if (!this.fileTransferMode){
						if(!raw.startsWith("<SYSTEM>") && !raw.startsWith("-") && !raw.startsWith("<") && raw.split(" ").length > 1 && !raw.startsWith("[ADMIN]") && JAVACARDMODE){}
							
						printScreen(raw);
					}
			}
			if(this.fileTransferMode){
				getFile(raw);
			}
		}
	}

	private int parseConsole(String text){
		String command = toLowerCases(text.split(" ")[0]);
		if (command.equals("/sendfile"))
			return isClientConnected ? SENDFILE : MSG;
		else if(command.equals("/exit") || command.equals("/logout"))
			return isClientConnected ? LOGOUT : MSG;
		else if(command.equals("/list"))
			return isClientConnected ? LIST : MSG;
		else if(command.equals("/msg"))
			return isClientConnected ? MSG : PRIVMSG;
		else if(command.equals("/broadcast"))
			return BROADCAST;
		else if(command.equals("/help"))
			return HELP;
		else if(command.equals("/test"))
			return TEST;
		else
			return MSG;
	}

	private void listenConsole() throws IOException {
		while(this.inConsole.hasNextLine()){
			String raw = this.inConsole.nextLine().trim();
			switch (parseConsole(raw)) {
				case SENDFILE: if(JAVACARDMODE){
						printScreen("test");
						sendCryptedFile(raw);}
						else{
							sendFile(raw);
						} break;
				case MSG: if (JAVACARDMODE){
					String[] newraw=raw.split(" ");
					sendServer(newraw[0] +" " + newraw[1] + " " + cipherMessage(newraw[2]) + " heavy");
					
				}  else sendServer(raw + " light"); break;
				case LIST: sendServer(raw); break;
				case PRIVMSG: sendServer(raw); break;
				case LOGOUT: logout(); break;
				case BROADCAST: 
					if(JAVACARDMODE){
						String[] parts=raw.split(" ");
						sendServer(parts[0] + " " + encryptBlock(parts[1]) + " heavy");
					}
					else{
						sendServer(raw + " light");
					}
					break;
					
				case HELP: displayHelp();break;
				case TEST: 
					encryptBlock("testtest");
				break;
			}
		}
	}

	@Override
	public void run() {
		try {
			listenNetwork();
		} catch (IOException e) {
			e.printStackTrace();
		}
	}

    public static void main( String[] args ) throws InterruptedException, IOException {
		Scanner s = new Scanner(System.in);
		System.out.print("Define server address: ");
		String ip = s.nextLine();
		System.out.print("Define server port: ");
		int port = Integer.parseInt(s.nextLine());
		try {
	    	new client.TheClient(ip, port);
		} catch (Exception e) {}
    }
}
