# @Author: schwarze_falke
# @Date:   2019-01-25T13:30:28-06:00
# @Last modified by:   schwarze_falke
# @Last modified time: 2019-01-25T13:32:08-06:00
import binascii

file = open("ethernet_1.bin", "rb")
byte = file.read()
print(bin(int(binascii.hexlify(byte),16)))
