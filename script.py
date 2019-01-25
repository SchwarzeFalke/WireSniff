# @Author: schwarze_falke
# @Date:   2019-01-25T13:30:28-06:00
# @Last modified by:   schwarze_falke
# @Last modified time: 2019-01-25T13:43:39-06:00
import binascii

def menu():
    file = open("ethernet_1.bin", "rb")
    binString = bin(int(binascii.hexlify(file.read()),16))
    file.close()
    print(hexConvert(binString[4:8]))

def hexConvert(varString):
    return hex(int(varString, 2))[2:]

menu()
