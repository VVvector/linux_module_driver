#!/usr/bin/python3

import serial
import time

def main():
    port_name = "/dev/ttyz1"
    time_val = 0.5

    p = serial.Serial(port_name, timeout=time_val)
    
    print("start write data")
    p.write('aa'.encode())

    print("start read data")
    p.readline()
    time.sleep(10)

    print("close the port")
    p.close()




if __name__ == "__main__":
    main()
 
