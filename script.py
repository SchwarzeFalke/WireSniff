# @Author: schwarze_falke
# @Date:   2019-01-25T13:30:28-06:00
# @Last modified by:   schwarze_falke
# @Last modified time: 2019-02-27T01:36:24-06:00
from bitstring import BitArray
import socket
from scapy.all import *
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


def findValueDict(value, key, file):
    JSONfile = open(file)
    JSONstr = JSONfile.read()
    JSONdata = json.loads(JSONstr)
    for entry in JSONdata:
        if str(value) == entry[key]:
            return entry
    return False


def dnsReading(binaryString):
    dnsData = binaryString
    dns_header = {
        "ID": None,
        "QR": None,
        "OPCODE": None,
        "AA": None,
        "TC": None,
        "RD": None,
        "RA": None,
        "Z": None,
        "RCODE": None,
        "QDCOUNT": None,
        "ANCOUNT": None,
        "NSCOUNT": None,
        "ARCOUNT": None
    }
    dns_question = {
        "QNAME": None,
        "QTYPE": None,
        "QCLASS": None
    }
    dns_answer = {
        "NAME": None,
        "TYPE": None,
        "CLASS": None,
        "TTL": None,
        "RDLENGTH": None,
        "RDATA": None
    }

    # DNS HEADER SECTION
    dns_header['ID'] = hex(int(binaryString[0:16], 2)).upper()[2:]
    dns_header['QR'] = binaryString[16:17]
    dns_header['OPCODE'] = int(binaryString[17:21], 2)
    dns_header['AA'] = binaryString[21:22]
    dns_header['TC'] = binaryString[22:23]
    dns_header['RD'] = binaryString[23:24]
    dns_header['RA'] = binaryString[24:25]
    dns_header['Z'] = binaryString[25:28]
    dns_header['RCODE'] = int(binaryString[28:32], 2)
    dns_header['QDCOUNT'] = int(binaryString[32:48], 2)
    dns_header['ANCOUNT'] = int(binaryString[48:64], 2)
    dns_header['NSCOUNT'] = int(binaryString[64:80], 2)
    dns_header['ARCOUNT'] = int(binaryString[80:96], 2)

    sitename, a = ascii_conv(binaryString[96:])
    dns_question['QNAME'] = sitename
    dns_question['QTYPE'] = int(binaryString[96+a:112+a], 2)
    dns_question['QCLASS'] = int(binaryString[112+a:128+a], 2)

    b = a
    sitename, a = ascii_conv(binaryString[128+b:144+b])
    dns_answer['QNAME'] = sitename
    dns_answer['TYPE'] = int(binaryString[144+a+b:160+a+b], 2)
    dns_answer['CLASS'] = int(binaryString[160+a+b:172+a+b], 2)
    dns_answer['TTL'] = int(binaryString[172+a+b:204+a+b], 2)
    dns_answer['RDLENGTH'] = hex(
        int(binaryString[204+a+b:220+a+b], 2)).upper()[2:]

    if(dns_answer['CLASS'] == 1):
        dns_answer['RDATA'] = int(binaryString[220+a+b:252+a+b], 2)
    if(dns_answer['CLASS'] == 5):
        dns_answer['RDATA'] = dns_question['QNAME']
    if(dns_answer['CLASS'] == 13):
        dns_answer['RDATA'] = int(binaryString[220+a+b:252+a+b], 2)
    if(dns_answer['CLASS'] == 22 or dns_answer['CLASS'] == 13):
        dns_answer['RDATA'] = int(binaryString[220+a+b:252+a+b], 2)

    print("HEADER\n{}".format(json.dumps(dns_header, indent=2)))
    print("QUESTION\n{}".format(json.dumps(dns_question, indent=2)))
    print("ANSWER\n{}".format(json.dumps(dns_answer, indent=2)))


def ascii_conv(binaryString):
    start = 0
    end = 8
    top = len(binaryString)
    word = " "

    while(binaryString[start:end] != "00000000" and end < top):
        letter = int(binaryString[start:end], 2)
        try:
            word += binascii.unhexlify('%x' % letter).decode("utf-8")
        except:
            pass
        start += 8
        end += 8

    return(word, end)


def process_data(raw_data):
    hexString = str(binascii.hexlify(
        bytes(raw_data[0])))[2:-1]
    print("---------------------------------------------------------------------------")
    hexString = hexString.upper()
    #readInput = input('Ingrese el nombre del archivo a leer: ')
    #fileStr = "packages/" + readInput + ".bin"
    # with codecs.open(fileStr, 'rb+') as content_file:
    #    file = content_file.read()
    # All file's data is read an process as hex
    # hexString = str
    # binascii.hexlify(file).upper().decode('utf-8')

    # End of testing part

    # The origin address has a lenght of 6 bytes
    # also the destination address; so, 6x2 = 12
    # The type information has a lenght of 2 bytes
    originAddress = formatHexString(hexString[0:12], 2, 14)
    destinationAddress = formatHexString(hexString[12:24], 2, 14)
    type = hexString[24:28]
    print("Direccion MAC de origen: ", originAddress)
    print("Direccion MAC de destino: ", destinationAddress)
    print("Tipo: ", type)
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
                print(
                    "Bandera 3: Ultimo fragmentado ({})".format(flags[2]))
            elif flags[2] == "1":
                print(
                    "Bandera 3: Fragmento intermedio ({})".format(flags[2]))

            print("Posicion del fragmento: ", posFrag)

            print("Tiempo de vida (TTL): ", ttl)

            print("Protocolo: {} [{}] ({})".format(
                (dictionary('ip_protocol_numbers.json')
                    [protocol])['Protocol'],
                (dictionary('ip_protocol_numbers.json')[protocol])['Keyword'], protocol))

            if(protocol == 1):
                icmpType = int(ip[160:168], 2)
                icmpCode = int(ip[168:176], 2)
                icmpChecksum = hex(int(ip[176:192], 2)).upper()[2:]

                print("\tTipo: {}".format(dictionary('icmp_messages.json')
                                          [icmpType]['Message']))
                print("\tCodigo: {}".format(dictionary('icmp_codes.json')
                                            [icmpCode]['Message']))
                print("\tChecksum: {}".format(icmpChecksum))

            if(protocol == 6 or protocol == 17):
                originPort = int(ip[160:176], 2)
                originPortData = findValueDict(
                    originPort, 'port', "tcp_ports.json")
                destinyPort = int(ip[176:192], 2)
                destinyPortData = findValueDict(
                    destinyPort, 'port', "tcp_ports.json")

                sequenceNumber = int(ip[192:224], 2)
                acknowledgeNumber = int(ip[224:256], 2)
                headSize = hex(int(ip[256:260], 2)).upper()[2:]
                reserved = int(ip[260:263], 2)

                # Flags section
                ns = ip[224:225]
                cwr = ip[225:226]
                ece = ip[226:227]
                urg = ip[227:228]
                ack = ip[228:229]
                psh = ip[229:230]
                rst = ip[230:231]
                syn = ip[231:232]
                fin = ip[232:233]

                windowSize = int(ip[233:248], 2)
                checksumTCP = hex(int(ip[248:264], 2)).upper()[2:]
                urgentPointer = int(ip[264:280], 2)
                data = ip[280:]

                if(originPortData != False):
                    print(
                        "\tPuerto de origen: {} [{} - {}]".format(originPortData['port'], originPortData['name'], originPortData['descript']))
                else:
                    print("\tPuerto de origen: {}".format(originPort))

                if(destinyPortData != False):
                    print(
                        "\tPuerto de destino: {} [{} - {}]".format(destinyPortData['port'], destinyPortData['name'], destinyPortData['descript']))
                else:
                    print("\tPuerto de destino: {}".format(destinyPort))

                if(protocol == 6):
                    print("\tNum. de secuencia: {}".format(sequenceNumber))
                    print("\tNum. de acuse de recibo: {}".format(
                        acknowledgeNumber))
                    print("\tReservado: {}".format(reserved))
                    print("\tB A N D E R A S")
                    print(
                        "\t\tNS: {}\n\t\tCWR: {}\n\t\tECE: {}\n\t\tURG: {}\n\t\tACK: {}\n\t\tPSH: {}\n\t\tRST: {}\n\t\tSYN: {}\n\t\tFIN: {}".format(ns, cwr, ece, urg, ack, psh, rst, syn, fin))
                    print("\tVentana: {}".format(windowSize))
                    print("\tPuntero urgente: {}".format(urgentPointer))

                if(protocol == 17):
                    headSize = hex(int(ip[208:224], 2)).upper()[2:]
                    checksumTCP = hex(int(ip[224:240], 2)).upper()[2:]
                    data = ip[240:]

                print("\tLongitud de cabecera: {}".format(headSize))
                print("\tChecksum: {}".format(checksumTCP))

                if(originPort == 53):
                    print("\tD N S")
                    dnsReading(data)

            print("Suma de control de cabecera: ", controlHeader)

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

        receiv_mac_address = hexString[(
            44+(x*2)+(y*2)):(44+(2*(x*2))+(y*2))]
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
        print("Longitud de la direccion hardware: {} bytes".format(
            hardware_address))
        print("Longitud de la dirección protocolo: {} bytes".format(
            protocol_address))
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


# Main function
if __name__ == '__main__':
    while(True):
        sniff(iface="wlp2s0", prn=process_data, filter="ip", count=1)
