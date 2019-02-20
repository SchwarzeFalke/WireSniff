# @Author: schwarze_falke
# @Date:   2019-01-25T13:30:28-06:00
# @Last modified by:   schwarze_falke
# @Last modified time: 2019-02-20T02:49:49-06:00
from bitstring import BitArray
import codecs
import binascii
import json


# This function gives a string a defined format of the type "00:00:00"
# depending on the lenght [given by @top]. It returns a formatted string
def formatNetString(varString):
    finalString = ''
    for i in varString:
        finalString += i
        finalString += '.'
    return finalString[:-1]


def formatHexString(varString, top):
    finalString = ''
    a = 0
    b = 2
    while b != top:
        finalString += str(varString[a:b])
        a = b
        b += 2
        if(b != top):
            finalString += ':'
    return finalString


def dictionary(file):
    JSONfile = open(file)
    JSONstr = JSONfile.read()
    JSONdata = json.loads(JSONstr)
    return JSONdata


# Main function
if __name__ == '__main__':

    readInput = input('Ingrese el nombre del archivo a leer: ')
    fileStr = "packages/" + readInput + ".bin"
    with codecs.open(fileStr, 'rb+') as content_file:
        file = content_file.read()
    # All file's data is read an process as hex
    hexString = binascii.hexlify(file).upper().decode('utf-8')

    # End of testing part

    # The origin address has a lenght of 6 bytes
    # also the destination address; so, 6x2 = 12
    # The type information has a lenght of 2 bytes
    originAddress = formatHexString(hexString[0:12], 14)
    destinationAddress = formatHexString(hexString[12:24], 14)
    type = hexString[24:28]
    print("Direccion MAC de origen: ", originAddress)
    print("Direccion MAC de destino: ", destinationAddress)
    if type == '0800':
        print("Tipo: ", type, " (IPv4)")

        # IP has a lenght of 20 bytes
        ip = BitArray(hex=hexString[28:]).bin
        version = ip[0:4]
        header = ip[4:8]
        header = int(header, 2)
        service = ip[8:16]
        long = int(ip[16:32], 2)
        id = int(ip[32:48], 2)
        flags = ip[48:51]
        posFrag = int(ip[51:64], 2)
        ttl = int(ip[64:72], 2)
        protocol = int(ip[72:80], 2)
        controlHeader = int(ip[80:96], 2)
        originIP = int(ip[96:128], 2)
        destinyIP = int(ip[128:160], 2)

        if version == "0100":
            print("Version: IPv4")

            print("Cabecera: ", (header * 32), " bytes")

            if service[0:3] == "000":
                print("Servicio: ", service[0:3], "de rutina")
            elif service[0:3] == "001":
                print("Servicio: ", service[0:3], "Prioritario")
            elif service[0:3] == "010":
                print("Servicio: ", service[0:3], "Inmediato")
            elif service[0:3] == "011":
                print("Servicio: ", service[0:3], "Relampago")
            elif service[0:3] == "100":
                print("Servicio: ", service[0:3], "Invalidacion Relampago")
            elif service[0:3] == "101":
                print("Servicio: ", service[0:3], "Procesando Llamada critica \
                y de emergencia")
            elif service[0:3] == "110":
                print("Servicio: ", service[0:3], "Control de trabajo de \
                internet")
            elif service[0:3] == "111":
                print("Servicio: ", service[0:3], "Control de red")

            if service[4] == "0":
                print("Retardo: Normal (", service[4], ")")
            elif service[4] == "1":
                print("Retardo: Bajo (", service[4], ")")

            if service[5] == "0":
                print("Rendimiento: Normal (", service[5], ")")
            elif service[5] == "1":
                print("Rendimiento: Bajo (", service[5], ")")

            if service[6] == "0":
                print("Fiabilidad: Normal (", service[6], ")")
            elif service[6] == "1":
                print("Fiabilidad: Alta (", service[6], ")")

            print("Longitud: ", long)
            print("Identificador: ", id)

            print("Bandera 1: Reservado ({})".format(flags[0]))
            if flags[1] == "0":
                print("Bandera 2: Divisible ({})".format(flags[1]))
            elif flags[1] == "1":
                print("Bandera 2: No divisible DF ({})".format(flags[1]))

            if flags[2] == "0":
                print("Bandera 3: Ultimo fragmentado ({})".format(flags[2]))
            elif flags[2] == "1":
                print("Bandera 3: Fragmento intermedio ({})".format(flags[2]))

            print("Posicion del fragmento: ", posFrag)

            print("Tiempo de vida (TTL): ", ttl)

            print("Protocolo: {} [{}] ({})".format(
                  (dictionary('ip_protocol_numbers.json')[protocol])['Protocol'],
                  (dictionary('ip_protocol_numbers.json')[protocol])['Keyword'], protocol))

            if protocol == 1:
                icmpType = int(ip[160:168], 2)
                icmpCode = int(ip[168:176], 2)
                icmpChecksum = int(ip[176:192], 2)

                print("Tipo: {}".format(dictionary('icmp_messages.json')[icmpType]['Message']))
                print("Codigo: {}".format(dictionary('icmp_codes.json')[icmpCode]['Message']))
                print("Checksum: {}".format(icmpChecksum))

            print("Suma de control de cabecera: ", controlHeader)

            print("Direccion IP de origen: ", formatNetString(str(originIP)))
            print("Direccion IP de origen: ", formatNetString(str(destinyIP)))

        elif version == "0100":
            print("Version: IPv6")

    if type == '0806':
        # IP has a lenght of 20 bytes
        # TCP's lenght is 23
        ip = formatHexString(hexString[28:68], 42)
        tcp = formatHexString(hexString[68:114], 48)
        data = formatHexString(hexString[114:len(hexString)], (len(hexString)
                                                               - 112))
        print("IP: ", ip)
        print("Tipo: ", type, " (ARP)")
        print("TCP: ", tcp)
        print("Datos: ", data)
    if type == '8035':
        # IP has a lenght of 20 bytes
        # TCP's lenght is 23
        ip = formatHexString(hexString[28:68], 42)
        tcp = formatHexString(hexString[68:114], 48)
        data = formatHexString(hexString[114:len(hexString)], (len(hexString)
                                                               - 112))
        print("Tipo: ", type, " (RARP)")
        print("IP: ", ip)
        print("TCP: ", tcp)
        print("Datos: ", data)
    if type == '08DD':
        # IP has a lenght of 20 bytes
        # TCP's lenght is 23
        ip = formatHexString(hexString[28:68], 42)
        tcp = formatHexString(hexString[68:114], 48)
        data = formatHexString(hexString[114:len(hexString)], (len(hexString)
                                                               - 112))
        print("Tipo: ", type, " (IPv6)")
        print("IP: ", ip)
        print("TCP: ", tcp)
        print("Datos: ", data)
