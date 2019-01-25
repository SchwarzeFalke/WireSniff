# @Author: schwarze_falke
# @Date:   2019-01-25T13:30:28-06:00
# @Last modified by:   schwarze_falke
# @Last modified time: 2019-01-25T14:35:15-06:00
import binascii

def menu():
    file = open("ethernet_1.bin", "rb")
    hexString = binascii.hexlify(file.read()).upper()
    file.close()

    originAddress = formatString(hexString[0:12], 14)
    destinationAddress = formatString(hexString[12:24], 14)
    type = hexString[24:28]
    ip = formatString(hexString[28:68], 42)
    tcp = formatString(hexString[68:114], 48)
    data = formatString(hexString[114:len(hexString)], (len(hexString)-112))

    print "Direccion MAC de origen: ", originAddress
    print "Direccion MAC de destino: ", destinationAddress
    print "Tipo: ", type
    print "IP: ", ip
    print "TCP: ", tcp
    print "Datos: ", data

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
