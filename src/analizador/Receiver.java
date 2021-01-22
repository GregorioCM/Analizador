/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package analizador;

import java.util.Arrays;
import java.util.Date;
import java.util.Vector;
import jpcap.PacketReceiver;
import jpcap.packet.ARPPacket;
import jpcap.packet.ICMPPacket;
import jpcap.packet.IPPacket;
import jpcap.packet.Packet;
import jpcap.packet.TCPPacket;
import jpcap.packet.UDPPacket;

/**
 *
 * @author Gregorio
 */
public class Receiver implements PacketReceiver {
    
    private Interface savePacket;
    
    public Receiver(Interface _interface){
        savePacket = _interface;
    }
    
    @Override
    public void receivePacket(Packet _packet) {
        /*
        * Captura los paquete tcp ahora toca añadirlos a la tabla, ver si se puede obtener los datos que se contienen en el paqete
        *
        */
        if(_packet != null){
            Date time = new Date();
            Vector<String> rowTable = new Vector<>(6);

            if (_packet instanceof jpcap.packet.TCPPacket) {
                // TCP Packet 6
                TCPPacket packet = (TCPPacket)_packet;
                String sourceIP = packet.src_ip.toString();
                String destinationIP = packet.dst_ip.toString();
                String length = String.valueOf(packet.data.length);
                String data = Arrays.toString(packet.data);
                time.setTime(System.currentTimeMillis());
                rowTable.add(time.toString());
                rowTable.add(sourceIP.substring(1));
                rowTable.add(destinationIP.substring(1));
                rowTable.add("TCP");
                rowTable.add(length);
                rowTable.add(data);
                savePacket.updateTable(rowTable, (new PacketCapturate(_packet, 6)));

    //            String prueba = new String(packet.data, StandardCharsets.UTF_16LE);         
            } else if (_packet instanceof jpcap.packet.UDPPacket){
                // Packet UDP 11
                UDPPacket packet = (UDPPacket)_packet;
                String sourceIP = packet.src_ip.toString();
                String destinationIP = packet.dst_ip.toString();
                String length = String.valueOf(packet.data.length);
                String data = Arrays.toString(packet.data);
                time.setTime(System.currentTimeMillis());
                rowTable.add(time.toString());
                rowTable.add(sourceIP.substring(1));
                rowTable.add(destinationIP.substring(1));
                rowTable.add("UDP");
                rowTable.add(length);
                rowTable.add(data);
                savePacket.updateTable(rowTable, (new PacketCapturate(_packet, 11)));
                
            } else if (_packet instanceof jpcap.packet.ARPPacket){
                // Packet ARP (is packet in ethernet protocol)
                // Meter la dirrecion en n array int para poder motrarlo en hexadecimal la direcion MAC
                ARPPacket packet = (ARPPacket)_packet;
                
                String sourceMac = "";
                String destinationMac = "";
                String elementSource = "";
                String elementDestination = "";
                for(int i=0; i<packet.sender_hardaddr.length; ++i){
                    elementSource = Integer.toHexString(packet.sender_hardaddr[i]);
                    elementDestination = Integer.toHexString(packet.target_hardaddr[i]);
                    try{
                       sourceMac = sourceMac + elementSource.substring(elementSource.length()-2) + ":";
                    }catch(java.lang.StringIndexOutOfBoundsException exc){
                        sourceMac = sourceMac + "0" + elementSource + ":";
                    }
                    try{
                       destinationMac = destinationMac + elementDestination.substring(elementDestination.length()-2) + ":";
                    }catch(java.lang.StringIndexOutOfBoundsException exc){
                        destinationMac = destinationMac + "0" + elementDestination + ":";
                    }
                }
                sourceMac = sourceMac.substring(0, sourceMac.length()-1);
                destinationMac = destinationMac.substring(0, destinationMac.length()-1);
                String length = String.valueOf(packet.data.length);
                
                String data = "";
                if(packet.operation == 1){
                    data = "Who is " + destinationMac + " Tell " + "192.168." + packet.sender_protoaddr[2]
                            + "." + packet.sender_protoaddr[3];
                } else {
                    data = "192.168." + packet.sender_protoaddr[2]+ "." + packet.sender_protoaddr[3] +
                            " is at " + sourceMac;
                }
                
                time.setTime(System.currentTimeMillis());
                rowTable.add(time.toString());
                rowTable.add(sourceMac);
                rowTable.add(destinationMac);
                rowTable.add("ARP");
                rowTable.add(length);
                rowTable.add(data);
                savePacket.updateTable(rowTable, (new PacketCapturate(_packet, -1)));
                
            } else if (_packet instanceof jpcap.packet.ICMPPacket){
                // Packet ICMP 1
                ICMPPacket packet = (ICMPPacket)_packet;
                String sourceIP = packet.src_ip.toString();
                String destinationIP = packet.dst_ip.toString();
                String length = String.valueOf(packet.data.length);
                String data = Arrays.toString(packet.data);
                time.setTime(System.currentTimeMillis());
                rowTable.add(time.toString());
                rowTable.add(sourceIP.substring(1));
                rowTable.add(destinationIP.substring(1));
                rowTable.add("ICMP");
                rowTable.add(length);
                rowTable.add(data);
                savePacket.updateTable(rowTable, (new PacketCapturate(_packet, 1)));
                
            } else if (_packet instanceof jpcap.packet.IPPacket){
                // Packet IP 4
                IPPacket packet = (IPPacket)_packet;
                String sourceIP = packet.src_ip.toString();
                String destinationIP = packet.dst_ip.toString();
                String length = String.valueOf(packet.data.length);
                String data = Arrays.toString(packet.data);
                time.setTime(System.currentTimeMillis());
                rowTable.add(time.toString());
                rowTable.add(sourceIP.substring(1));
                rowTable.add(destinationIP.substring(1));
                rowTable.add("IP");
                rowTable.add(length);
                rowTable.add(data);
                savePacket.updateTable(rowTable, (new PacketCapturate(_packet, 4)));
                
            } else {
                // other Packet
            }
        }
    }

}
