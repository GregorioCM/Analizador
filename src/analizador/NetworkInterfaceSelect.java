/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package analizador;
import jpcap.*;


/**
 *
 * @author Gregorio
 */
public class NetworkInterfaceSelect {
    private NetworkInterface network;
    
    public NetworkInterfaceSelect(){ network = null; }
    
    public NetworkInterfaceSelect(NetworkInterface _network) { network = _network; }
    
    public void setElement(NetworkInterface _network) { network = _network; }
    public NetworkInterface getElement() { return network; }
}
