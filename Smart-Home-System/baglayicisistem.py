#!/usr/bin/env python
# ! -*- coding: utf-8 -*-

import threading
import socket
import queue

import sys
import geopy
import socket
import threading
from PyQt5.QtCore import *
import rsa
from PyQt5.QtWidgets import *
from PyQt5.uic import loadUi
import queue
import time
import functools

from datetime import datetime


# bagalayici sistemin dosyasi. RG,IG,HE,PK,PT,CS,QU komutlarini algiliyor yani tanisma protokollerini,
# baglanti koparma ve kendi listesini gonderme.
# Baska bir komut gelirse, BSH( baglayici sistem hatasi) yolluyor karsiya. veya direkt ER yolliyabilir (bakmali).

class ReadThreadServer(threading.Thread):
    def __init__(self, uuid, host, port, csoc, address,  threadQueue, komsuFihristi, my_public_key,
                 my_private_key):
        threading.Thread.__init__(self)
        # self.name = name
        self.uuid = uuid
        self.nickname = None
        self.csoc = csoc
        self.address = address
        self.tQueue = threadQueue
        self.komsuFihristi = komsuFihristi

        self.my_public_Key = my_public_key
        self.my_private_key = my_private_key
        self.host = host
        self.port = port
        self.istemciID = 0
        self.istemciDurum = False

        self.kisi_var_mi = False
        self.uuid1 = 0  # rg
        self.uuid2 = 0  # ig

        # b
        self.kullanici_ip = ""
        self.kullanici_port = 0
        self.kullanici_geo = ""
        self.kullanici_tipi = ""
        self.kullanici_ismi = ""
        self.kullanici_engelDurumu = False
        self.kullanici_publickey = None

    def parser(self, dataInByte):
        print(dataInByte)

        if dataInByte[0:2] == "RG".encode():
            data = dataInByte.decode()

            parsedData = dataInByte.decode().split(":")
            self.uuid1 = int(parsedData[1])
            for key in self.komsuFihristi.keys():  # Komsu fihristinde daha onceden var mi?
                if (int(parsedData[1]) == key):
                    self.kisi_var_mi = True
                    self.istemciID = key
                    break
            if self.kisi_var_mi:  # Komsu fihristinde daha onceden var.


                    self.istemciDurum = True
                    self.tQueue.put(data.replace("RG", "RO"))
            else:  # Kisi listesinde yok mu?
                self.tQueue.put(data.replace("RG", "RNN"))  # kisi listesinde yok ama ekleniyo ?
        elif dataInByte[0:3] == "END".encode():
            self.tQueue.put("END")

        elif dataInByte[0:5] == "BEGIN".encode():

            self.tQueue.put(dataInByte.decode())

        # elif parsedData[0] == "IG":
        elif dataInByte[0:2] == "IG".encode():
            data = dataInByte.decode()

            parsedData = dataInByte.decode().split(":")
            if (len(parsedData) > 1):
                self.uuid2 = parsedData[1]
                if int(self.uuid1) == int(self.uuid2):
                    print("olduuu")
                    self.istemciDurum = True
                    self.istemciID = int(self.uuid1)
                   # 1. value: abone_mi
                    # 2. value: ben_ona_abone_mi
                    # 3. value: bende_engellemi(self.komsuFihristi[int(self.kullanici_uuid)][5])
                    # 4. value: ben_onda_engellimi

                    self.komsuFihristi[int(parsedData[1])] = [parsedData[2], parsedData[3], parsedData[4],
                                                              parsedData[5],
                                                              parsedData[6], parsedData[7], parsedData[8],
                                                              parsedData[9]]
                    self.kisi_var_mi = True
                    self.tQueue.put("OG:" + str(self.uuid))
                else:
                    self.tQueue.put("RN")
            elif (len(parsedData) == 1):
                self.tQueue.put("OG" + str(self.uuid))
            else:
                self.tQueue.put("RN")


        elif dataInByte[0:2] == "HE".encode():
            data = dataInByte.decode()

            parsedData = dataInByte.decode().split(":")
            self.tQueue.put(data + ":" + str(self.uuid))


        # elif parsedData[0] == "PK" and self.istemciDurum == True:
        elif dataInByte[0:2] == "PK".encode() and self.istemciDurum == True:
            data = dataInByte.decode()

            parsedData = dataInByte.decode().split(":")


            self.tQueue.put("PK:" + str(self.my_public_Key.n) + ":" + str(self.my_public_Key.e))  # pubk (n,e)
            if parsedData[1] != None or parsedData[2] != None:
                    self.kullanici_publickey = rsa.key.PublicKey(int(parsedData[1]), int(parsedData[2]))
            else:
                    self.kullanici_publickey = None
                    self.tQueue.put("PN")

        # elif parsedData[0] == "PT" and self.istemciDurum == True:
        elif dataInByte[0:2] == "PT".encode() and self.istemciDurum == True:

            sifreliMetin = dataInByte[3:].strip()
            print(self.komsuFihristi)


            decrypt_uuid = rsa.decrypt(sifreliMetin, self.my_private_key)
            if int(self.uuid) == int(decrypt_uuid.decode()):
                if self.kullanici_publickey == None:
                        self.tQueue.put("PO")
                else:
                        encrypt_kullanici_uuid = rsa.encrypt(str(self.istemciID).encode(), self.kullanici_publickey)
                        # self.tQueue.put("PO:" + encrypt_kullanici_uuid)
                        self.csoc.send("PO:".encode() + encrypt_kullanici_uuid)
                        # self.tQueue.put("PO:".encode() + encrypt_kullanici_uuid)
        elif dataInByte[0:8] == "CO:BEGIN".encode():
            print("buraya")
            print(dataInByte)
            self.tQueue.put(str(dataInByte.decode()))
        # elif data[0:2] == "CS":
        elif dataInByte[0:2] == "CS".encode():
            num = int(dataInByte.decode().split(":")[1])
            if (len(self.komsuFihristi) < num): num = len(self.komsuFihristi)
            geoloc = self.komsuFihristi.get(self.istemciID)[5]
            counter = 0  # num sayısına varmamız icin tutulan deger
            list = []

                # self.tQueue.put("CO:BEGIN")
            for i in self.komsuFihristi:
                if (self.komsuFihristi[i][5] == geoloc):
                        list.append(str("CO:" + str(i) + ":" + str(self.komsuFihristi[i][0]) + ":" + str(
                            self.komsuFihristi[i][1]) + ":" + str(self.komsuFihristi[i][2]) + ":" + str(
                            self.komsuFihristi[i][3]) + ":" + str(self.komsuFihristi[i][4]) + ":" + str(
                            self.komsuFihristi[i][5]) + ":" + str(
                            self.komsuFihristi[i][6] + ":" + str(self.komsuFihristi[i][7]))))

                        counter += 1
                        if (counter == num):
                            self.tQueue.put(','.join(list))
                            print(','.join(list))
                            break
            # self.tQueue.put("CO:END")
        elif dataInByte[0:2] == "AV".encode():
            print("gelmis")
            print(dataInByte)
            self.tQueue.put(str(dataInByte.decode()))





        # elif data[0:2] == "QU":
        elif dataInByte[0:2] == "QU".encode() and self.istemciDurum == True:
            data = dataInByte.decode()
            parsedData = dataInByte.decode().split(":")
            self.tQueue.put("BY")

        elif dataInByte[0:2] == "QU".encode() and self.istemciDurum == True:
            data = dataInByte.decode()
            parsedData = dataInByte.decode().split(":")
            self.tQueue.put("BY")

        elif dataInByte == "quit".encode() :
            self.tQueue.put("BY")


        else:
            self.tQueue.put("ER")

    def run(self):
        while True:
            incoming_data = self.csoc.recv(1024)
            self.parser(incoming_data.strip())
            if (incoming_data.strip()[0:2] == "QU".encode() or incoming_data.strip() =="quit".encode()):
                print("read thread server QU dasın ")
                break


class ServerThread(threading.Thread):
    def __init__(self, uuid, ip, port, talepFihristi, arzFihristi, komsuArzFihristi, komsuTalepFihristi,
                 komsuFihristi,
                 abonelikFihristi, my_public_key, my_private_key):
        threading.Thread.__init__(self)
        self.talepFihristi = talepFihristi
        self.arzFihristi = arzFihristi
        self.komsuArzFihristi = komsuArzFihristi
        self.komsuFihristi = komsuFihristi
        self.komsuTalepFihristi = komsuTalepFihristi
        self.abonelikFihristi = abonelikFihristi
        self.s = socket.socket()

        self.ip = ip
        self.port = int(port)
        self.my_public_key = my_public_key
        self.my_private_key = my_private_key
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                          1)  # bunu port'u tekrar kullanabilmek için yazdım. yoksa OS boşaltana kadar bayağı bekliyorsunuz serverı başlatırken.
        self.s.bind((self.ip, self.port))
        self.s.listen()
        self.uuid = uuid

    def run(self):
        while True:
            c, addr = self.s.accept()

            # fakat tqueue, write thread ve read thread her kullanıcı için unique olmalı. bu yüzden onları burada yaratıp başlatıyoruz.

            yeniThreadQueue = queue.Queue()

            yeniWriteThreadServer = WriteThreadServer(c, addr, yeniThreadQueue)
            yeniReadThreadServer = ReadThreadServer(self.uuid, self.ip, self.port, c, addr,
                                                    yeniThreadQueue,
                                                    self.komsuFihristi, self.abonelikFihristi, self.talepFihristi,
                                                    self.arzFihristi, self.komsuArzFihristi, self.komsuTalepFihristi,
                                                    self.my_public_key, self.my_private_key)

            yeniWriteThreadServer.start()
            yeniReadThreadServer.start()


class WriteThreadServer(threading.Thread):
    def __init__(self, csoc, address, threadQueue):
        threading.Thread.__init__(self)
        self.csoc = csoc
        self.address = address
        self.tqueue = threadQueue

    def run(self):
        while True:
            queueMessage = self.tqueue.get()
            self.csoc.send((queueMessage + '\n').encode())
            if queueMessage[0:2] == "BY":
                break
        self.csoc.close()

class ServerThread(threading.Thread):
    def __init__(self, uuid, ip, port, komsuFihristi,
                my_public_key, my_private_key):
        threading.Thread.__init__(self)

        self.komsuFihristi = komsuFihristi

        self.s = socket.socket()

        self.ip = ip
        self.port = int(port)
        self.my_public_key = my_public_key
        self.my_private_key = my_private_key
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                          1)  # bunu port'u tekrar kullanabilmek için yazdım. yoksa OS boşaltana kadar bayağı bekliyorsunuz serverı başlatırken.
        self.s.bind((self.ip, self.port))
        self.s.listen()
        self.uuid = uuid

    def run(self):
        while True:
            c, addr = self.s.accept()

            # fakat tqueue, write thread ve read thread her kullanıcı için unique olmalı. bu yüzden onları burada yaratıp başlatıyoruz.

            yeniThreadQueue = queue.Queue()

            yeniWriteThreadServer = WriteThreadServer(c, addr, yeniThreadQueue)
            yeniReadThreadServer = ReadThreadServer(self.uuid,self.ip , self.port,c, addr,  yeniThreadQueue,
                                                    self.komsuFihristi,
                                                    self.my_public_key, self.my_private_key)

            yeniWriteThreadServer.start()
            yeniReadThreadServer.start()


def main():
    uuid = 15
    # port range= 1025 47808/
    # buradadaki degiskenler grub uyeleri kendileri manuel olarak degistirmeli kendine uyarliyip simulasion yapabilmek icin
    host = "0.0.0.0"
    port = 3005
    sistemTipi = 'B'
    geoloc = "kordinat"
    kullaniciAdi = "B"

    # Public / Private Key tanımlamaları
    (my_public_key, my_private_key) = rsa.newkeys(256)


    komsuFihristi = { 3: ["0.0.0.0", 2266, None, 8, 9, "kordinat", "Mert", "A"],
                      4: ["0.0.0.0", 2267, None, 10, 11, "kordinat", "Süheyla", "A"],
                      1: ["0.0.0.0", 2268,None, 12, 13, "kordinat", "Beyza", "A"],
                      5: ["0.0.0.0", 9999, None, 8, 9, "kordinat", "gggg", "A"],
                      6: ["0.0.0.0", 8888, None, 10, 11, "kordinat", "ssss", "A"],
                     7: ["0.0.0.0", 7777, None, 12, 13, "kordinat", "bbbb", "A"]
                      }





    serverth = ServerThread(uuid, host, port,   komsuFihristi,
                            my_public_key, my_private_key)
    serverth.start()


if __name__ == "__main__":
    main()
