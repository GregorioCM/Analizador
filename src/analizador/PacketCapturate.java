/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package analizador;

import jpcap.packet.Packet;
/**
 *
 * @author Gregorio
 */
public class PacketCapturate {
    private Packet packet;
    private int protocolType;
    
    
    public PacketCapturate() {}
            
    public PacketCapturate(Packet _packet, int _protocolType){
        packet = _packet;
        protocolType = _protocolType;
    }
    
    public PacketCapturate(PacketCapturate _packet){
        packet = _packet.packet;
        protocolType = _packet.protocolType;
    }
    
    public Packet getPacket() { return packet; }
    public int getProtocol() { return protocolType; }
    
    public void setPacket(Packet _packet) { packet = _packet; }
    public void setProtocolType(int _protocolType) { protocolType = _protocolType; }
}
