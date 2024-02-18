package secureApp.server;

import secureApp.server.Models.Client;

import java.io.*;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.logging.*;
import java.util.stream.Collectors;

import opencard.core.service.*;
import opencard.core.terminal.*;
import opencard.core.util.*;
import opencard.opt.util.*;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;
import java.util.Random;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.PrivateKey;
import java.security.Security;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import javax.crypto.Cipher;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class ServiceChat implements Runnable {

    private  boolean JAVACARDMODE = true;

    private Socket socket;
    private Client client;
    private final Scanner in;

    
    private static final String LOGOUT = "LOGOUT"; 
    private static final String LIST = "LIST"; 
    private static final String PRIVMSG = "PRIVMSG"; 
    private static final String MSG = "MSG"; 
    private static final String SENDFILE = "SENDFILE"; 

    
    private static final String ISUSERCONNECTED = "ISUSERCONNECTED";

    private final int NBMAXUSERCONNECTED;
    private boolean fileTransferMode = false;
    private PrintWriter outRetrievingClient;

    public static final Map<String, PrintWriter> connectedClients = new HashMap<>();
    public static List<Client> registeredClients = new LinkedList<>();

    private KeyFactory factory;
	private PublicKey pub;
    private final int DATASIZE = 128;	
    

    public ServiceChat(Socket socket, int NBMAXUSERCONNECTED) throws IOException {
        this.socket = socket;
        this.NBMAXUSERCONNECTED = NBMAXUSERCONNECTED;
        this.in = new Scanner(socket.getInputStream());
        this.client = new Client(new PrintWriter(socket.getOutputStream(), true), socket);
    }

    private synchronized void generateRSAKeys(Client client) throws Exception {

        byte[] modulus_b = Base64.getDecoder().decode(client.getRSAModulus());
        byte[] public_exponent_b = Base64.getDecoder().decode(client.getRSAExponent());
     
        // Transform byte[] into String
		String mod_s =  HexString.hexify( modulus_b );
		mod_s = mod_s.replaceAll( " ", "" );
		mod_s = mod_s.replaceAll( "\n", "" );

		String pub_s =  HexString.hexify( public_exponent_b );
		pub_s = pub_s.replaceAll( " ", "" );
		pub_s = pub_s.replaceAll( "\n", "" );

		// Load the keys from String into BigIntegers 
		BigInteger modulus = new BigInteger(mod_s, 16);
		BigInteger pubExponent = new BigInteger(pub_s, 16);

		// Create private and public key specs from BinIntegers 
		RSAPublicKeySpec publicSpec = new RSAPublicKeySpec(modulus, pubExponent);

		// Create the RSA private and public keys 
		this.factory = KeyFactory.getInstance("RSA");
		this.pub = factory.generatePublic(publicSpec);
    }

    private synchronized boolean checkConnectionsNumber() throws IOException {
        if (ServiceChat.connectedClients.size() >= NBMAXUSERCONNECTED){
            this.client.getOut().println("<SYSTEM> User connected limit reached");
            this.client.getOut().close();
            this.socket.close();
            return true;
        }
        return false;
    }

    private synchronized void broadcast(String username, String msg, boolean system){
        String[] parts=msg.split(" ");
        if(parts.length==3){
            final String x = system ? "<" + username + ">" + " " + msg : "BROADCAST [" + username + "]" + " " + parts[1] + " " +parts[2];
            for(Map.Entry<String, PrintWriter> client : connectedClients.entrySet())
                client.getValue().println(x);
        }
        else if(parts.length==2){
            final String x = system ? "<" + username + ">" + " " + msg : "BROADCAST [" + username + "]" + " " + parts[1];
            for(Map.Entry<String, PrintWriter> client : connectedClients.entrySet())
                client.getValue().println(x);
        }
        else{
            final String x =msg;
            for(Map.Entry<String, PrintWriter> client : connectedClients.entrySet())
                client.getValue().println(x);
        }        
        
    }

    private synchronized void isUserConnected(String raw) {
        String[] splitRaw = raw.split(" ");
        boolean isfound = false;
        for (Map.Entry<String, PrintWriter> retrievingClient : connectedClients.entrySet()){
            if (splitRaw[3].equals(retrievingClient.getKey())) {
                this.client.getOut().println("<SYSTEM> [SENDFILE]: User is connected: " + splitRaw[3] + " sending: " + splitRaw[4]);
                isfound = true;
            }
        }
        if(!isfound)
            this.client.getOut().println("<SYSTEM> [SENDFILE]: User is not connected");
    }

    private synchronized boolean usernameExists(String username){
        boolean exist = false;

        for (Client client: registeredClients)
            if (client.getUsername().equals(username)) {
                exist = true;
                break;
            }
        return exist;
    }

    private synchronized boolean authentication() throws IOException {
        this.client.getOut().println("<SYSTEM> Welcome!");
        this.client.getOut().println("<SYSTEM> Enter your username");
        String username = this.in.nextLine().trim();

        if(!username.toLowerCase(Locale.ROOT).equals("admin")) {
            if (!usernameExists(username)) {
                signUp(username);
                return false; 
            } else {
                login(username);
                return true;
            }

        } else {
            this.client.setUsername("Forbidden username");
            logout(this.client);
            return false;
        }
    }

    private byte[] generateChallenge() throws Exception {
		Random r = new Random((new Date()).getTime());
		byte[] challengeBytes = new byte[DATASIZE];
		r.nextBytes(challengeBytes);
		challengeBytes[0] = (byte)((byte) 0x00 + (byte)(new Random().nextInt(0x8f - 0x00 + 0x01)));
		
		return challengeBytes;
    }

    private String encryptChallenge(byte[] challengeBytes) throws Exception {
		
		Security.addProvider(new BouncyCastleProvider());
		Cipher cRSA_NO_PAD = Cipher.getInstance("RSA/NONE/NoPadding", "BC");

        cRSA_NO_PAD.init(Cipher.ENCRYPT_MODE, this.pub);
		byte[] ciphered = new byte[DATASIZE];
		cRSA_NO_PAD.doFinal(challengeBytes, 0, DATASIZE, ciphered, 0);
		

        return Base64.getEncoder().encodeToString(ciphered);
    }

    private synchronized boolean cardLogin(String username) throws IOException {
        this.client.getOut().println("<SYSTEM> Connecting...");
        
        int isFound = -1;

        for (Client client : registeredClients)
            if (client.getUsername().equals(username))
                isFound = registeredClients.indexOf(client);

        if (isFound == -1) {
            this.client.getOut().println("<SYSTEM> Username is not registered");
            this.client.getOut().close();
            this.socket.close();
            return false;
        }

        if(!checkConnectionsNumber()) {
            if (connectedClients.containsKey(username)) {
                this.client.getOut().println("<SYSTEM> User already connected");
                
                this.client.getOut().close();
                this.socket.close();
            } else {
                try {
                    
                    generateRSAKeys(registeredClients.get(isFound));

                    
                    byte[] challengeBytes = generateChallenge();
                    String encryptedChallengeBytesB64 = encryptChallenge(challengeBytes);

                    this.client.getOut().println("<SYSTEM> AUTHENTICATION NEW " + encryptedChallengeBytesB64);
                
                    String challengeBytesDecryptedB64 = null;
                    while (this.in.hasNextLine()) {
                        String raw = this.in.nextLine().trim();
                        if(raw.startsWith("<SYSTEM> AUTHENTICATION SOLVED ")) {
                            
                            challengeBytesDecryptedB64 = raw.split(" ")[3];
                            break;
                        }
                    }

                    if (Arrays.equals(challengeBytes, Base64.getDecoder().decode(challengeBytesDecryptedB64))) {
                        this.client.getOut().println("<SYSTEM> Authentication success");
                        

                        registeredClients.get(isFound).setOut(this.client.getOut()); 
                        registeredClients.get(isFound).setSocket(this.client.getSocket());
                        this.client = registeredClients.get(isFound);

                        this.client.getOut().println("<SYSTEM> Connected as: " + this.client.getUsername());
                       
                        broadcast("SYSTEM", this.client.getUsername() + " is now connected!", true);

                        connectedClients.put(this.client.getUsername(), this.client.getOut());
                        listClients();

                        return true;
                    } else {
                        this.client.getOut().println("<SYSTEM> Authentication error");
                     
                        return false;
                    }
                } catch( Exception e ) {
                    System.out.println("initNewCard: " + e);
                }
            }
        }
        return false;
    }

    private synchronized boolean cardAuthentication() throws IOException {
        this.client.getOut().println("<SYSTEM> Welcome!");
        this.client.getOut().println("<SYSTEM> Enter your username");
        String username = this.in.nextLine().trim();

        if(!username.toLowerCase(Locale.ROOT).equals("admin")) {
            if(!usernameExists(username)){
                cardRegister(username);
                return false;
            } else {
                return cardLogin(username); 
            }
        } else {
            this.client.setUsername("Forbidden username");
            logout(this.client);
            return false;
        }
    }

    private synchronized void cardRegister(String username) throws IOException {
        this.client.getOut().println("<SYSTEM> Register");
        this.client.setUsername(username);

        this.client.getOut().println("<SYSTEM> REGISTRATION NEW");

        while (this.in.hasNextLine()) {
            String raw = this.in.nextLine().trim();
            if(raw.startsWith("<SYSTEM> REGISTRATION MODULUS")) {
                
                this.client.setRSAModulus(raw.split(" ")[3]);
            } else if (raw.startsWith("<SYSTEM> REGISTRATION EXPONENT")) {
                
                this.client.setRSAExponent(raw.split(" ")[3]);
            }
            if (this.client.getRSAModulus() != null && this.client.getRSAExponent() != null) {
                break;
            } 
        }

        registeredClients.add(this.client);

        
        this.client.getOut().println("<SYSTEM> Registration Successful");
        this.socket.close();
    }

    private synchronized void signUp(String username) throws IOException {
        this.client.getOut().println("<SYSTEM> Register");
        this.client.setUsername(username);

        String password = "";
        String confirmPassword = " ";
        while(!password.equals(confirmPassword)){
            this.client.getOut().println("Enter password: ");
            password = this.in.nextLine().trim();
            this.client.getOut().println("Confirm password: ");
            confirmPassword = this.in.nextLine().trim();
        }
        this.client.setPassword(password);

        registeredClients.add(this.client);

       
        this.client.getOut().println("<SYSTEM> Registration Successful");
        this.socket.close();
    }

    private synchronized void login(String username) throws IOException {
        this.client.getOut().println("<SYSTEM> Connecting...");
        int isFound = -1;

        this.client.getOut().println("Enter password: ");
        String password = this.in.nextLine();

        for (Client client : registeredClients)
            if (client.getUsername().equals(username) && client.getPassword().equals(password))
                isFound = registeredClients.indexOf(client);

        if (isFound == -1) {
            this.client.getOut().println("<SYSTEM> Username or password is incorrect");
            this.client.getOut().close();
            this.socket.close();
            return;
        }

        if(!checkConnectionsNumber()) {
            if (connectedClients.containsKey(username)) {
                this.client.getOut().println("<SYSTEM> User already connected");
             
                this.client.getOut().close();
                this.socket.close();
            } else {
                registeredClients.get(isFound).setOut(this.client.getOut()); 
                registeredClients.get(isFound).setSocket(this.client.getSocket()); 
                this.client = registeredClients.get(isFound);

                this.client.getOut().println("<SYSTEM> Connected as: " + this.client.getUsername());
            
                broadcast("SYSTEM", this.client.getUsername() + " is now connected!", true);

                connectedClients.put(this.client.getUsername(), this.client.getOut());
                listClients();
            }
        }
    }

    private synchronized void logout(Client client) throws IOException {
        try {
            for (Client rc: registeredClients) 
                if (client.getUsername().equals(rc.getUsername())) 
                    for (Map.Entry<String, PrintWriter> retrievingClient : connectedClients.entrySet())
                        if (client.getUsername().equals(retrievingClient.getKey())) {
                            connectedClients.remove(client.getUsername());
                            client.getOut().println("<SYSTEM> Disconnecting...");
                            
                            broadcast("SYSTEM", client.getUsername() + " is now disconnected!", true);
                            client.getOut().close();
                            client.getSocket().close();
                        }
        } catch (Exception e) {
        }
    }

    private synchronized void listClients(){
        this.client.getOut().println("<SYSTEM> [LIST]: Connected users: ");
        this.client.getOut().println("-----------------------------");
        for(Map.Entry<String, PrintWriter> client : connectedClients.entrySet()) {
            String key = client.getKey();
            this.client.getOut().print("<" + key + "> ");
        }
        this.client.getOut().println("\n-----------------------------");
  
    }



    private synchronized void privateMessage(String raw) {
        String[] splitRaw = raw.split(" ");
        System.out.println(splitRaw.length);
        if(splitRaw.length == 4 ) {
            for (Client rc: registeredClients) {
                if (splitRaw[1].equals(rc.getUsername())) {
                    for (Map.Entry<String, PrintWriter> client : connectedClients.entrySet()) {
                        if (rc.getUsername().equals(client.getKey())) {
                            client.getValue().println("[From: " + this.client.getUsername() + "]" + " " + splitRaw[2] + " " + splitRaw[3]);
                            return;
                        }
                    }
                    this.client.getOut().println("<SYSTEM> [PRIVMSG]: Private message cancelled, " + rc.getUsername() + " is not connected");
                    return;
                }
            }
        }
        if(splitRaw.length == 3 ) {
            for (Client rc: registeredClients) {
                if (splitRaw[1].equals(rc.getUsername())) {
                    for (Map.Entry<String, PrintWriter> client : connectedClients.entrySet()) {
                        if (rc.getUsername().equals(client.getKey())) {
                            client.getValue().println("[From: " + this.client.getUsername() + "]" + " " + splitRaw[2] );
                            return;
                        }
                    }
                    this.client.getOut().println("<SYSTEM> [PRIVMSG]: Private message cancelled, " + rc.getUsername() + " is not connected");
                    return;
                }
            }
        }
        this.client.getOut().println("<SYSTEM> [PRIVMSG]: Private message cancelled");
    }  

        

    

    private synchronized void sendFile(String raw) { 
        if(!fileTransferMode) {
            String[] splitRaw = raw.split(" ");

            boolean userFound = false;
            for (Map.Entry<String, PrintWriter> retrievingClient : connectedClients.entrySet()) {
                if (splitRaw[1].equals(retrievingClient.getKey())) {
                    userFound = true;
                    this.client.getOut().println("<SYSTEM> [SENDFILE]: Sending " + splitRaw[2] + " to user: " + retrievingClient.getKey());
                    this.outRetrievingClient = retrievingClient.getValue();
                    this.outRetrievingClient.println("<SYSTEM> [SENDFILE]: SENDFILESTART: Retrieving " + splitRaw[2] + " from " + this.client.getUsername());
                    this.fileTransferMode = true;
                    break;
                }
            }
            if(!userFound){
                this.fileTransferMode = false;
                this.client.getOut().println("<SYSTEM> [SENDFILE]: Sending failed, User: " + splitRaw[1] + " is not connected");
            }
        } else { 
            if (raw.equals("<SYSTEM> [SENDFILE]: SENDFILESTOP")){
                this.outRetrievingClient.println("<SYSTEM> [SENDFILE]: SENDFILESTOP");
                this.client.getOut().println("<SYSTEM> [SENDFILE]: File Sent");
                this.fileTransferMode = false;
            } else {
                if (raw.startsWith("<SYSTEM> [SENDFILE]"))
                    this.outRetrievingClient.println(raw);
                else
                    broadcast(this.client.getUsername(), raw, false);
            }
        }
    }

    private String parseReceived(String text){
        if(text.startsWith("<SYSTEM> [SENDFILE]: ISUSERCONNECTED"))
            return ISUSERCONNECTED;
        else{
            switch (text.split(" ")[0].toLowerCase(Locale.ROOT)) {
                case "/exit", "/logout" -> {return LOGOUT;}
                case "/list" -> {return LIST;}
                case "/msg" -> {return PRIVMSG;}
                case "/sendfile"->{return  SENDFILE;}
                case "/broadcast" -> {return MSG;}
                
                default -> {return MSG;}
            }
        }
    }

    @Override
    public void run() {
        String test = this.in.nextLine().trim();
        if(test.equals("2")){
            this.JAVACARDMODE=false;
        }
        try {
            if ((JAVACARDMODE && cardAuthentication()) || (!JAVACARDMODE && authentication())) {
                while (this.in.hasNextLine()) {
                    String raw = this.in.nextLine().trim();

                    if(fileTransferMode)
                        sendFile(raw);
                    else {
                        switch (parseReceived(raw)) {
                            case LOGOUT -> {
                                
                                logout(this.client);
                                return;
                                
                            }
                            case LIST -> listClients();
                            case PRIVMSG -> privateMessage(raw);
                            case MSG -> {
                                String[] parts=raw.split(" ");
                                broadcast(this.client.getUsername(), raw, false);}
                            
                            case SENDFILE -> sendFile(raw);
                            case ISUSERCONNECTED -> isUserConnected(raw);
                        }
                    }
                }
            }
            logout(this.client);
        } catch (IOException e) {
            e.printStackTrace();
        }
    }
}

