# @Author: schwarze_falke
# @Date:   2019-01-25T11:14:07-06:00
# @Last modified by:   schwarze_falke
# @Last modified time: 2019-01-25T12:01:09-06:00

with open("ethernet_1", "rb") as f:
    byte = f.read(1)
    while byte:
        # Do stuff with byte.
        byte = f.read(1)
        print(byte)
