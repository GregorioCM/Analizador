/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package analizador;

import java.net.SocketException;
import java.util.Arrays;
import java.util.logging.Level;
import java.util.logging.Logger;
import jpcap.*;

/**
 *
 * @author Gregorio
 */
public class NetworkInterfaceSelect {
    private jpcap.NetworkInterface network;
    
    public NetworkInterfaceSelect(){ network = null; }
    
    public NetworkInterfaceSelect(java.net.NetworkInterface _network){ 
        this.instanceNetwork(_network);
    }
    
    public void setElement(java.net.NetworkInterface _network){ 
        this.instanceNetwork(_network);
    }
    
    public jpcap.NetworkInterface getElement() { return network; }
    
    // Initialize network variable
    private void instanceNetwork(java.net.NetworkInterface _network){
        this.network = null;
        jpcap.NetworkInterface[] networkList = JpcapCaptor.getDeviceList();
        int i = 0;
        do{
            try {
                if(Arrays.equals(_network.getHardwareAddress(), networkList[i].mac_address)){
                    network = networkList[i];
                }
            } catch (SocketException ex) {
                System.out.println("Error en la comparacion de direcciones MAC");
                Logger.getLogger(NetworkInterfaceSelect.class.getName()).log(Level.SEVERE, null, ex);
            }
            ++i;
        }while(this.network == null);
    }
}
