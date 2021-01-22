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
        
        jpcap.NetworkInterface[] networkList = JpcapCaptor.getDeviceList();
        for(int i=0; i<networkList.length; ++i){
            try {
                if(Arrays.equals(_network.getHardwareAddress(), networkList[i].mac_address)){
                    network = networkList[i];
                }
            } catch (SocketException ex) {
                System.out.println("Error en la comparacion de direcciones MAC");
                Logger.getLogger(NetworkInterfaceSelect.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    
    public void setElement(java.net.NetworkInterface _network){ 
        jpcap.NetworkInterface[] networkList = JpcapCaptor.getDeviceList();
        for(int i=0; i<networkList.length; ++i){
            try {
                if(Arrays.equals(_network.getHardwareAddress(), networkList[i].mac_address)){
                    network = networkList[i];
                }
            } catch (SocketException ex) {
                System.out.println("Error en la comparacion de direcciones MAC");
                Logger.getLogger(NetworkInterfaceSelect.class.getName()).log(Level.SEVERE, null, ex);
            }
        }
    }
    public jpcap.NetworkInterface getElement() { return network; }
}
