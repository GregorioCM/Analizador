/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package analizador;

import java.io.IOException;
import jpcap.JpcapCaptor;
import jpcap.PacketReceiver;

/**
 *
 * @author Gregorio
 */
public class ThreadSniffing extends Thread{
    private NetworkInterfaceSelect networkSelect;
    private JpcapCaptor captor;
    private Receiver packetReciever;
    boolean stopCapturing;
    
    public ThreadSniffing (){
        networkSelect = null;
        captor = null;
        packetReciever = null;
        stopCapturing = false;;
    }
    
    public ThreadSniffing (NetworkInterfaceSelect _networkSelect, Receiver _packetReciever) throws IOException {
        networkSelect = _networkSelect;
        captor = JpcapCaptor.openDevice(networkSelect.getElement(), 65535, false, -1);
        packetReciever = _packetReciever;
        stopCapturing = false;
    }
    
    public void setNetworkSelect (NetworkInterfaceSelect _networkSelect) { networkSelect = _networkSelect; }
    
    public void defineCaptor () throws IOException{
        if (networkSelect != null){
            captor = JpcapCaptor.openDevice(networkSelect.getElement(), 65535, false, -1);
        }
    }
    
    public void run(){
        if(captor != null){
            do{
                packetReciever.receivePacket(captor.getPacket());
            }while(stopCapturing == false);
            captor.close();
            this.interrupt();
        }
    }
}
