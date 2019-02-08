# @Author: schwarze_falke
# @Date:   2019-01-25T13:30:28-06:00
# @Last modified by:   schwarze_falke
# @Last modified time: 2019-02-08T11:39:22-06:00
import binascii

# Main function
def menu():
    file = open(input('Ingrese el nombre del archivo a leer: '), "rb")
    hexString = binascii.hexlify(file.read()).upper()       # All file's data is read an process as hex
    file.close()

    originAddress = formatString(hexString[0:12], 14)       # The origin address has a lenght of 6 bytes
    destinationAddress = formatString(hexString[12:24], 14) # also the destination address; so, 6x2 = 12
    type = hexString[24:28]                                 # The type information has a lenght of 2 bytes

    print "Direccion MAC de origen: ", originAddress
    print "Direccion MAC de destino: ", destinationAddress
    if type == '0800':
        print "Tipo: ", type, " (IPv4)"
        ip = bin(int(hexString[28:68], 16))[4:]  # IP has a lenght of 20 bytes
        print "IP: ", ip
        version = ip[0:4]
        header = ip[4:4]
        header = int(header)
        print header
        if version == "0010":
            print "Version: IPv4"
        elif version == "0100":
            print "Version: IPv6"

    if type == '0806':
        ip = formatString(hexString[28:68], 42)  # IP has a lenght of 20 bytes
        tcp = formatString(hexString[68:114], 48)               # TCP's lenght is 23
        data = formatString(hexString[114:len(hexString)], (len(hexString)-112))
        print "IP: ", ip
        print "Tipo: ", type, " (ARP)"
        print "TCP: ", tcp
        print "Datos: ", data
    if type == '8035':
        ip = formatString(hexString[28:68], 42)  # IP has a lenght of 20 bytes
        tcp = formatString(hexString[68:114], 48)               # TCP's lenght is 23
        data = formatString(hexString[114:len(hexString)], (len(hexString)-112))
        print "Tipo: ", type, " (RARP)"
        print "IP: ", ip
        print "TCP: ", tcp
        print "Datos: ", data
    if type == '08DD':
        ip = formatString(hexString[28:68], 42)  # IP has a lenght of 20 bytes
        tcp = formatString(hexString[68:114], 48)               # TCP's lenght is 23
        data = formatString(hexString[114:len(hexString)], (len(hexString)-112))
        print "Tipo: ", type, " (IPv6)"
        print "IP: ", ip
        print "TCP: ", tcp
        print "Datos: ", data

# This function gives a string a defined format of the type "00:00:00"
# depending on the lenght [given by @top]. It returns a formatted string
def formatString(varString, top):
    finalString = ''
    a = 0
    b = 2
    while b != top:
        finalString += varString[a:b]
        a = b
        b += 2
        if(b != top):
            finalString += ':'
    return finalString

menu()
