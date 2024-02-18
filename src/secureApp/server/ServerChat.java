package secureApp.server;

import java.net.*;
import java.io.*;
import java.util.Scanner;
import java.util.logging.*;

public class ServerChat {

    private final static int NBMAXUSERCONNECTED = 3;
    protected static boolean runServer = true;
    public static final Logger logger = Logger.getLogger(ServiceChat.class.getSimpleName());

    public ServerChat(final int port){
        

        try(ServerSocket listener = new ServerSocket(port)) {
            
            while (runServer) new Thread(new ServiceChat(listener.accept(), NBMAXUSERCONNECTED)).start();
           
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void main(String[] argv){
        new ServerChat(7777);
    }
}