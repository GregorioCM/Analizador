/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */

package analizador;

import java.io.*;
import java.lang.*;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
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
                String source = Arrays.toString(packet.sender_hardaddr);
                int i = packet.sender_hardaddr[1];  
                String destination = Arrays.toString(packet.target_hardaddr);
                String length = String.valueOf(packet.data.length);
                String data = "Who is " + Arrays.toString(packet.target_hardaddr);
                
                time.setTime(System.currentTimeMillis());
                rowTable.add(time.toString());
                rowTable.add(source);
                rowTable.add(destination);
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
