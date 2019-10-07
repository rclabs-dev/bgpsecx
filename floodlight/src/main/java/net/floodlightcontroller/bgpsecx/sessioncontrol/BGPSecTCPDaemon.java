package net.floodlightcontroller.bgpsecx.sessioncontrol;

import java.net.InetAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.io.IOException;

import net.floodlightcontroller.bgpsecx.general.BGPSecDefs;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BGPSecTCPDaemon implements Runnable{
	protected static Logger log = LoggerFactory.getLogger(BGPSecTCPDaemon.class);
	protected String srvIPAddr = BGPSecDefs.IP_TO_LISTEN;
    protected int srvPort   = BGPSecDefs.BGP_PORT;
    protected int socketQueue = BGPSecDefs.SOCKET_QUEUE;			
    protected ServerSocket serverSocket = null;
    protected boolean      isStopped    = false;
    protected Thread       runningThread= null;

    public BGPSecTCPDaemon(String srvIPAddr, int srvPort, int socketQueue){
    	this.srvIPAddr = srvIPAddr;
        this.srvPort = srvPort;
        this.socketQueue = socketQueue;
    }

    public void run(){
    	synchronized(this){
    		this.runningThread = Thread.currentThread();
    	}
        openServerSocket();
        while(! isStopped()){
            Socket clientSocket = null;
            try {
                clientSocket = this.serverSocket.accept();
            } catch (IOException e) {              
                throw new RuntimeException("Error accepting client connection", e);
            }
            new Thread(
                new BGPSecClientHandle(clientSocket)
            ).start();
        }
        log.info("By admin, the BGP Server for speakers connection stopped.");
    }


    private synchronized boolean isStopped() {
        return this.isStopped;
    }

    public synchronized void stop(){
        this.isStopped = true;
        try {
            this.serverSocket.close();
        } catch (IOException e) {
            throw new RuntimeException("Error closing server", e);
        }
    }

    private void openServerSocket() {
        try {
            this.serverSocket = 
            		new ServerSocket(this.srvPort, 
            		this.socketQueue, InetAddress.getByName(this.srvIPAddr));
            log.info("BGP daemon was started and listening on address " + this.srvIPAddr + ":" + this.srvPort);
        } catch (IOException | NullPointerException e) {
            throw new RuntimeException("Cannot binding BGP port.", e);
        }
    }

}