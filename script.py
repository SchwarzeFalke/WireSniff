# @Author: schwarze_falke
# @Date:   2019-01-25T13:30:28-06:00
# @Last modified by:   schwarze_falke
# @Last modified time: 2019-02-27T01:36:24-06:00
from bitstring import BitArray
import codecs
import binascii
import json


# This function gives a string a defined format of the type "00:00:00"
# depending on the length [given by @top]. It returns a formatted string
def formatNetString(varString):
    finalString = ''
    i = 0
    while(i < len(varString)):
        if(i+2 > len(varString)):
            break
        finalString += str(int(varString[i:i+2], 16)) + '.'
        i += 2
    return finalString[:-1]


def formatHexString(varString, type, top):
    finalString = ''
    a = 0
    b = type
    while b != top:
        finalString += str(varString[a:b])
        a = b
        b += type
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
    originAddress = formatHexString(hexString[0:12], 2, 14)
    destinationAddress = formatHexString(hexString[12:24], 2, 14)
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
        controlHeader = hex(int(ip[80:96], 2)).upper()[2:]
        originIP = str(int(ip[96:104], 2)) + "." + str(int(ip[104:112], 2)) + \
            "." + str(int(ip[112:120], 2)) + "." + str(int(ip[120:128], 2))
        destinyIP = str(int(ip[128:136], 2)) + "." + str(int(ip[136:144], 2)) + \
            "." + str(int(ip[144:152], 2)) + "." + str(int(ip[152:160], 2))

        print(originIP)
        print(destinyIP)
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
                  (dictionary('ip_protocol_numbers.json')
                   [protocol])['Protocol'],
                  (dictionary('ip_protocol_numbers.json')[protocol])['Keyword'], protocol))

            if protocol == 1:
                icmpType = int(ip[160:168], 2)
                icmpCode = int(ip[168:176], 2)
                icmpChecksum = hex(int(ip[176:192], 2)).upper()[2:]

                print("\tTipo: {}".format(dictionary('icmp_messages.json')
                                          [icmpType]['Message']))
                print("\tCodigo: {}".format(dictionary('icmp_codes.json')
                                            [icmpCode]['Message']))
                print("\tChecksum: {}".format(icmpChecksum))

            print("Suma de control de cabecera: ", controlHeader)

            print("Direccion IP de origen: {}".format(originIP))
            print("Direccion IP de origen: {}".format(destinyIP))

        elif version == "0100":
            print("Version: IPv6")

    if type == '0806':
        # IP has a lenght of 20 bytes
        # TCP's lenght is 23
        hardware = int(hexString[28:32], 16)
        protocol = hexString[32:36]
        x = hardware_address = int(hexString[36:38], 16)
        y = protocol_address = int(hexString[38:40], 16)
        opcode = int(hexString[40:44], 16)

        trans_mac_address = hexString[44:(44+(x*2))]
        trans_ip_address = hexString[(44+(x*2)):(44+(x*2)+(y*2))]

        receiv_mac_address = hexString[(44+(x*2)+(y*2)):(44+(2*(x*2))+(y*2))]
        receiv_ip_address = hexString[(
            44+(2*(x*2))+(y*2)):(44+(2*(x*2))+(2*(y*2)))]
        print("Tipo: {} (ARP)".format(type))
        print("Tipo de Hardware: {} ({})".format(
            dictionary('hardware_type_arp.json')[hardware]['Type'],
            hardware
        ))
        if(protocol == '0800'):
            print("Protocolo: IPv4 ({})".format(protocol))
        elif(protocol == '0806'):
            print("Protocolo: ARP ({})".format(protocol))
        elif(protocol == '0835'):
            print("Protocolo: RARP ({})".format(protocol))
        elif(protocol == '086DD'):
            print("Protocolo: IPv6 ({})".format(protocol))
        print("Longitud de la direccion hardware: {} bytes".format(hardware_address))
        print("Longitud de la dirección protocolo: {} bytes".format(protocol_address))
        if(opcode == 1):
            print("Solicitud ARP")
        elif(opcode == 2):
            print("Respuesta ARP")
        elif(opcode == 3):
            print("Solicitud RARP")
        elif(opcode == 4):
            print("Respuesta RARP")

        print("Dirección hardware del emisor (MAC): {}".format(formatHexString(trans_mac_address, 2,
                                                                               len(trans_mac_address) + 2)))
        print("Dirección IP del emisor: {}".format(
            formatNetString(trans_ip_address)))

        print("Dirección hardware del receptor (MAC): {}".format(formatHexString(receiv_mac_address, 2,
                                                                                 len(receiv_mac_address) + 2)))
        print("Dirección IP del receptor: {}".format(
            formatNetString(receiv_ip_address)))
    if type == '8035':
        # IP has a lenght of 20 bytes
        # TCP's lenght is 23
        ip = formatHexString(hexString[28:68], 2, 42)
        tcp = formatHexString(hexString[68:114], 2, 48)
        data = formatHexString(hexString[114:len(hexString)], 2, (len(hexString)
                                                                  - 112))
        print("Tipo: ", type, " (RARP)")
        print("IP: ", ip)
        print("TCP: ", tcp)
        print("Datos: ", data)
    if type == '86DD':

        version = int((hexString[28:29]), 16)
        traffic = BitArray(hex=hexString[29:31]).bin
        flowLabel = int((hexString[31:36]), 16)
        dataSize = int((hexString[36:40]), 16)
        nextHeader = int((hexString[40:42]), 16)
        jumpLimit = int((hexString[42:44]), 16)
        originAddress = hexString[44:76]
        destinationAddress = hexString[76:108]
        icmpType = int((hexString[108:110]), 16)
        icmpCode = int((hexString[110:112]), 16)
        icmpChecksum = hexString[112:116]

        print("Tipo: {} (IPv6)".format(type))
        print("Version: {}".format(version))

        if traffic[0:3] == "000":
            print("Trafico: ", traffic[0:3], "de rutina")
        elif traffic[0:3] == "001":
            print("Trafico: ", traffic[0:3], "Prioritario")
        elif traffic[0:3] == "010":
            print("Trafico: ", traffic[0:3], "Inmediato")
        elif traffic[0:3] == "011":
            print("Trafico: ", traffic[0:3], "Relampago")
        elif traffic[0:3] == "100":
            print("Trafico: ", traffic[0:3], "Invalidacion Relampago")
        elif traffic[0:3] == "101":
            print("Trafico: ", traffic[0:3], "Procesando Llamada critica \
            y de emergencia")
        elif traffic[0:3] == "110":
            print("Trafico: ", traffic[0:3], "Control de trabajo de \
            internet")
        elif traffic[0:3] == "111":
            print("Trafico: ", traffic[0:3], "Control de red")

        if traffic[4] == "0":
            print("Retardo: Normal (", traffic[4], ")")
        elif traffic[4] == "1":
            print("Retardo: Bajo (", traffic[4], ")")

        if traffic[5] == "0":
            print("Rendimiento: Normal (", traffic[5], ")")
        elif traffic[5] == "1":
            print("Rendimiento: Bajo (", traffic[5], ")")

        if traffic[6] == "0":
            print("Fiabilidad: Normal (", traffic[6], ")")
        elif traffic[6] == "1":
            print("Fiabilidad: Alta (", traffic[6], ")")

        print("Etiqueta de flujo: {}".format(flowLabel))
        print("Tamano de datos: {}".format(dataSize))

        print("Encabezado siguiente: {} [{}] ({})".format(
            (dictionary('ip_protocol_numbers.json')
             [nextHeader])['Protocol'],
            (dictionary('ip_protocol_numbers.json')[nextHeader])['Keyword'], nextHeader))

        print("Limite de salto: {}".format(jumpLimit))

        print("Direccion origen: {}".format(
            formatHexString(originAddress, 4, 36)))
        print("Direccion destino: {}".format(
            formatHexString(destinationAddress, 4, 36)))

        if (nextHeader == 58):
            print("\tICMP Tipo: {}\n\tICMP Codigo: {}".format(dictionary('icmpv6_codes.json')
                                                        [icmpType]['Message'], dictionary(
                                                            'icmpv6_codes.json')
                                                        [icmpType]['Code'][icmpCode]['Description']))
            print("\tICMP Checksum: {}".format(icmpChecksum))
