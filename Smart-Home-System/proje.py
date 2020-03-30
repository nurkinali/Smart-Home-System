#!/usr/bin/env python
# ! -*- coding: utf-8 -*-

import threading
import socket
import queue

import sys
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


# projedeki sunucu için basit bir başlangıç dosyasıdır.

# sunucunun kod ikeleti bu. unutulmaması gereken nokta şu ki bütün istekler sunuculara gidiyor. sunucu da cevap veiyor.
# sunucu request atmıyor. sadece dış istemciden gelen isteğe cevap verecek ve kendi istemcilerine bi şeyler söyleyecek şekilde tasarlanmalı.
# peer sistemi olacak. merkezi olmasa da bu yine de çoklu bağlantı demek olacak. sunucu sürekli bağlantı bekler halde olmalı yani.
# her sunucunun 1 write, 1 read threadi olmalı. çünkü gelen istekleri alması ve


IstemcilerFihristi = {}



class LogThread(threading.Thread):
    def __init__(self, logQueue, Filename):
        threading.Thread.__init__(self)
        self.lqueue = logQueue
        self.fname = Filename

    def run(self):
        with open(self.fname, 'w+') as f:
            while True:
                data = self.lqueue.get()

                f.write("%s %s \r " % (time.strftime("%a, %d %b %Y %H:%M:%S ", time.gmtime()), data))
                f.flush()
                pass



class ReadThreadIstemci(threading.Thread):
    def __init__(self, csoc, writeQueue, screenQueue, uuid, ip, port, selfIP, selfPORT, sistemTipi, geoloc, nickname,
                 my_public_key, my_private_key, arzFihristi, talepFihristi, komsuFihristi,abonelikFihristi,komsuArzFihristi, komsuTalepFihristi,lQueue):
        threading.Thread.__init__(self)
        self.csoc = csoc
        self.nickname = nickname
        self.ip = ip
        self.port = port
        self.selfIP = selfIP
        self.selfPORT = selfPORT
        self.uuid = uuid
        self.arzFihristi = arzFihristi
        self.talepFihristi = talepFihristi
        self.sistemTipi = sistemTipi
        self.geoloc = geoloc
        self.my_public_key = my_public_key
        self.my_private_key = my_private_key
        self.writeQueue = writeQueue
        self.screenQueue = screenQueue
        self.serverID = "" #bağlandığımız kişinin uuidsi
        self.komsuFihristi=komsuFihristi
        self.abonelikFihristi=abonelikFihristi
        self.komsuArzFihristi=komsuArzFihristi
        self.komsuTalepFihristi = komsuTalepFihristi
        self.serverIP=""    #bağlandığımız kişinin ip'si
        self.serverPORT=""  #bağlandığımız kişinin portu
        self.lQueue=lQueue


    def incoming_parser(self, dataInByte):

        """data = dataInByte.decode()

        parsedData = dataInByte.decode().split(":")
        """
        anlamli_data = ""
        if len(dataInByte) == 0:
            return

        if dataInByte[0:2] == "OG".encode():
            data = dataInByte.decode()
            uuid=data.split(":")[1]
            anlamli_data = str(uuid) + " kullanicisiyla olan tanisma onaylandi."
            self.lQueue.put("OG islemi basarili")
            self.writeQueue.put("PK:" + str(self.my_public_key.n) + ":" + str(self.my_public_key.e))

        elif dataInByte[0:2] == "ON".encode():
            anlamli_data = "UUID testi basarisiz."
            #self.csoc.close()


        # test_uuid = data.split(":")[1]
        # print(test_uuid)
        # print(self.responseuuid)
        # if test_uuid == self.responseuuid:
        #   anlamli_data = str(self.responseuuid) + " kullanisina olan baglanti basarili. Tanisma islemi basliyor"

        #  tanisma_komutu = "RG" + ":" + str(self.uuid) + ":" + str(self.ip) + ":" + str(
        #       self.port) + ":" + self.geoloc + ":" + self.sistemTipi + ":" + self.nickname
        #   self.writeQueue.put(tanisma_komutu)

        #  else:
        #      anlamli_data = "UUID testi basarisiz tekrar baglanti kurmayi deneyin."
        #   self.csoc.close()

        elif dataInByte[0:2] == "BY".encode():
            anlamli_data = "Baglanti sonlandirildi"


        elif dataInByte[0:2] == "HE".encode():
            data = dataInByte.decode()
            self.serverID = data.split(":")[1]
            anlamli_data = str(self.serverID) + " kullanicisi size merhaba diyor."
            self.lQueue.put("HE islemi basarili"+str(self.serverID)+" karsidan gelen ")
            print("HE lqueue olmasi lazim normalde")
            t = time.localtime()

            pt = "%02d/%02d/%02d" % (t.tm_hour, t.tm_min, t.tm_sec)

            pt = "%02d.%02d.%02d" % (t.tm_hour, t.tm_min, t.tm_sec)

            self.writeQueue.put("RG" + ":" + str(self.uuid) + ":" + str(self.selfIP) + ":" + str(self.selfPORT) + ":" + pt + ":"
                  + str(self.my_public_key.e)+ ":" +  str(self.my_public_key.n) + ":" + "kordinat" + ":"  + self.nickname
                   + ":" + self.sistemTipi)
            print("RG" + ":" + str(self.uuid) + ":" + str(self.selfIP) + ":" + str(self.selfPORT) + ":" + pt + ":"
                  + str(self.my_public_key.e)+ ":" +  str(self.my_public_key.n) + ":" + "kordinat" + ":"  + self.nickname
                   + ":" + self.sistemTipi)
        elif dataInByte[0:2] == "RO".encode():
            anlamli_data = "Tanisma onaylandi."

        elif dataInByte[0:2] == "TN".encode():
            anlamli_data = "Alisveris basarili degil!"
        elif dataInByte[0:2] == "RN".encode():
            data = dataInByte.decode()
            if data[0:3] == "RNN":
                anlamli_data = "ID kontrolleri yapiliyor."
                self.lQueue.put("ID esleme basarili"+str(self.uuid)+"ve" +str(self.serverID)+" arasi")
                self.writeQueue.put(data.replace("RNN", "IG"))
            elif data[0:4] == "RNBT":
                anlamli_data = "Bu kullanıcı engellenmişti."
            elif data[0:4] == "RNBF":
                anlamli_data = "Bu kullanıcının engeli kaldırılmıştı."
            elif data[0:4] == "RNBB":
                anlamli_data = "Engellenmeden engel kaldırılamaz."
            elif data[0:4] == "RNUT":
                anlamli_data = "Üye olunmuştu."
            elif data[0:4] == "RNUF":
                anlamli_data = "Üyelikten çıkılmıştı."
            elif data[0:4] == "RNUO":
                anlamli_data = "Üye olmadan üyelikten çıkılmaz."
            elif(self.abonelikFihristi[int(self.serverID)][3]==True):
                anlamli_data = "Karşı sistemde engellisiniz."
            else:
                anlamli_data = "Bu kişi sende engelli."


        elif dataInByte[0:5] == "BEGIN".encode():

            anlamli_data = "CO:BEGIN"

            data = str(dataInByte.decode())

            #print(data[0:5])

            data = data.replace("BEGIN", "CS")

            #print(data)

            # self.writeQueue.put(str(dataInByte.decode()).replace("CO:BEGIN", "CS"))

            self.writeQueue.put(data)


        elif dataInByte[0:6] != "CO:END".encode() and dataInByte[0:8] != "CO:BEGIN".encode() and dataInByte[

                                                                                                 0:2] == "CO".encode():
            #print("1")
           # print(dataInByte)
           # print(type(dataInByte.decode()))
            #print(list(dataInByte))

            if ("," in str(dataInByte)):


                anlamli_data = dataInByte.decode().split(",")[0]
                if (int(str(dataInByte.decode()).split(":")[1]) != int(self.uuid)):
                    self.komsuFihristi[int(str(dataInByte.decode()).split(":")[1])] = [
                        str(dataInByte.decode()).split(":")[2],
                        int(str(dataInByte.decode()).split(":")[3]),
                        str(dataInByte.decode()).split(":")[4],
                        int(str(dataInByte.decode()).split(":")[5]),
                        int(str(dataInByte.decode()).split(":")[6]),
                        str(dataInByte.decode()).split(":")[7],
                        str(dataInByte.decode()).split(":")[8],
                        str(dataInByte.decode()).split(":")[9]]


                data = dataInByte.decode().replace(dataInByte.decode().split(",")[0] + ",", "")

                self.writeQueue.put("AV;" + str(data))

               # print(data)

            else:
                if (int(str(dataInByte.decode()).split(":")[1]) != int(self.uuid)):
                    self.komsuFihristi[int(str(dataInByte.decode()).split(":")[1])] = [
                        str(dataInByte.decode()).split(":")[2],
                        int(str(dataInByte.decode()).split(":")[3]),
                        str(dataInByte.decode()).split(":")[4],
                        int(str(dataInByte.decode()).split(":")[5]),
                        int(str(dataInByte.decode()).split(":")[6]),
                        str(dataInByte.decode()).split(":")[7],
                        str(dataInByte.decode()).split(":")[8],
                        str(dataInByte.decode()).split(":")[9]]
                self.writeQueue.put("END")

                anlamli_data = str(dataInByte.decode())
                print("anlamli data CO2:")
                print(anlamli_data)



        elif dataInByte[0:2] == "AV".encode():

            if ("," in str(dataInByte)):

                if (int(str(dataInByte.decode()).split(":")[1]) != int(self.uuid)):
                    self.komsuFihristi[int(str(dataInByte.decode()).split(":")[1])] = [
                        str(dataInByte.decode()).split(":")[2],
                        int(str(dataInByte.decode()).split(":")[3]),
                        str(dataInByte.decode()).split(":")[4],
                        int(str(dataInByte.decode()).split(":")[5]),
                        int(str(dataInByte.decode()).split(":")[6]),
                        str(dataInByte.decode()).split(":")[7],
                        str(dataInByte.decode()).split(":")[8],
                        str(dataInByte.decode()).split(":")[9]]

                anlamli_data = dataInByte.decode().split(",")[0].replace("AV;", "")
                print("anlamli data CO3:")
                print(anlamli_data)

                data = dataInByte.decode().replace(dataInByte.decode().split(",")[0] + ",", "")

                self.writeQueue.put("AV;" + str(data))

                #print(data)

            else:
                if(int(str(dataInByte.decode()).split(":")[1]) != int(self.uuid)):
                    self.komsuFihristi[int(str(dataInByte.decode()).split(":")[1])] = [
                        str(dataInByte.decode()).split(":")[2],
                        int(str(dataInByte.decode()).split(":")[3]),
                        str(dataInByte.decode()).split(":")[4],
                        int(str(dataInByte.decode()).split(":")[5]),
                        int(str(dataInByte.decode()).split(":")[6]),
                        str(dataInByte.decode()).split(":")[7],
                        str(dataInByte.decode()).split(":")[8],
                        str(dataInByte.decode()).split(":")[9]]

                data = str(dataInByte.decode()).split(";")[1].replace("AV;", "")




                anlamli_data = data
                if (int(str(dataInByte.decode()).split(":")[1]) != int(self.uuid)):
                    self.komsuFihristi[int(str(dataInByte.decode()).split(":")[1])] = [
                        str(dataInByte.decode()).split(":")[2],
                        int(str(dataInByte.decode()).split(":")[3]),
                        str(dataInByte.decode()).split(":")[4],
                        int(str(dataInByte.decode()).split(":")[5]),
                        int(str(dataInByte.decode()).split(":")[6]),
                        str(dataInByte.decode()).split(":")[7],
                        str(dataInByte.decode()).split(":")[8],
                        str(dataInByte.decode()).split(":")[9]]

                self.writeQueue.put("END")


        elif dataInByte[0:3] == "END".encode():

            anlamli_data = "CO:END"

        elif dataInByte[0:2] == "PK".encode():
            data = dataInByte.decode()
            keys_array = data.split(":")

            kullanici_pub_key = rsa.key.PublicKey(int(keys_array[1]), int(keys_array[2]))  # pubk(n,e)
            crypted_message = rsa.encrypt(str(self.serverID).encode(), kullanici_pub_key)

            self.csoc.sendall("PT:".encode() + crypted_message)
            # self.csoc.sendall( crypted_message)

            anlamli_data = "Public key alısverisi gerceklesti"
            self.lQueue.put("PK islemi basarili")

        elif dataInByte[0:2] == "PO".encode():
            print("Po ya geldik sukur")
            anlamli_data = "Sifre testi başarili"
            self.lQueue.put("PO islemi basarili "+str(self.serverID)+"ve"+str(self.uuid)+" arasi")

        elif dataInByte[0:2] == "PN".encode():
            anlamli_data = ""


        elif dataInByte[0:2] == "TO".encode():
            print(dataInByte.decode())
            type = dataInByte.decode().split(":")[1]
            uuid = dataInByte.decode().split(":")[2]
            if (type == "T"):
                serverTalepFiyat = int(self.talepFihristi.get((int(uuid)))[5]) / int(
                    self.talepFihristi.get((int(uuid)))[2])
                clientAdet = dataInByte.decode().split(":")[4]
                serverAdet = self.talepFihristi.get((int(uuid)))[2]
                if (float(clientAdet) >= float(serverAdet)):
                    del self.talepFihristi[int(uuid)]
                    for i in len(self.komsuArzFihristi.get(int(self.serverID))):
                        if self.komsuArzFihristi.get(int(self.serverID))[i][0] == int(uuid):
                            self.komsuArzFihristi.get(int(self.serverID))[i][3] = \
                            self.komsuArzFihristi.get(int(self.serverID))[i][3] - serverAdet
                            self.komsuArzFihristi.get(int(self.serverID))[i][6] = \
                            self.komsuArzFihristi.get(int(self.serverID))[i][6] - (serverTalepFiyat * serverAdet)
                    print("Yeniler:")
                    print(self.talepFihristi)
                    print(self.komsuArzFihristi)
                else:
                    for i in len(self.komsuArzFihristi.get(int(self.serverID))):
                        if self.komsuArzFihristi.get(int(self.serverID))[i][0] == int(uuid):
                            del self.komsuArzFihristi.get(int(self.serverID))[i]
                    print("Yeniler2:")
                    print(self.talepFihristi)
                    print(self.komsuArzFihristi)
                    serverAdet = float(serverAdet) - float(clientAdet)
                    self.talepFihristi.get(int(uuid))[2] = serverAdet
                    self.talepFihristi.get(int(uuid))[5] = serverTalepFiyat * serverAdet
                    print(self.talepFihristi)
                anlamli_data = "Alisveris basarili"
            if (type == "A"):
                serverArzFiyat = int(self.arzFihristi.get((int(uuid)))[5]) / int(self.arzFihristi.get((int(uuid)))[2])
                clientAdet = dataInByte.decode().split(":")[4]
                serverAdet = self.arzFihristi.get((int(uuid)))[2]
                if (float(clientAdet) >= float(serverAdet)):
                    del self.arzFihristi[int(uuid)]
                    for i in range(len(self.komsuTalepFihristi.get(int(self.serverID)))):
                        if self.komsuTalepFihristi.get(int(self.serverID))[i][0] == int(uuid):
                            self.komsuTalepFihristi.get(int(self.serverID))[i][3] = \
                            self.komsuTalepFihristi.get(int(self.serverID))[i][3] - serverAdet
                            self.komsuTalepFihristi.get(int(self.serverID))[i][6] = \
                            self.komsuTalepFihristi.get(int(self.serverID))[i][6] - (serverArzFiyat * serverAdet)
                    print("Yeniler:")
                    print(self.arzFihristi)
                    print(self.komsuTalepFihristi)

                else:
                    for i in range(len(self.komsuTalepFihristi.get(int(self.serverID)))):
                        if self.komsuTalepFihristi.get(int(self.serverID))[i][0] == int(uuid):
                            del self.komsuTalepFihristi.get(int(self.serverID))[i]
                    print("Yeniler2:")
                    print(self.arzFihristi)
                    print(self.komsuTalepFihristi)
                    serverAdet = float(serverAdet) - float(clientAdet)
                    self.talepFihristi(int(uuid))[2] = serverAdet
                    self.talepFihristi(int(uuid))[5] = serverArzFiyat * serverAdet
                anlamli_data = "Alisveris basarili"


        elif dataInByte[0:2] == "DO".encode():
            list = []
            virguldenAyrilmisData = dataInByte.decode().split(",")
            for i in range(len(virguldenAyrilmisData)):
                parsedData = virguldenAyrilmisData[i].split(":")
                if parsedData[1] == "BEGIN":
                    anlamli_data = "Talepler alinmaya baslaniyor."
                elif parsedData[1] == "END":
                    anlamli_data = "Talep alma islemi sonlandi."
                else:
                    try:
                        talep = parsedData[1:]
                        list.append(
                            [int(parsedData[1]), parsedData[2], parsedData[3], int(parsedData[4]), parsedData[5],
                             parsedData[6], int(parsedData[7])])
                        anlamli_data = str(talep)
                    except:
                        anlamli_data = (talep[0] + " talebinin yapisi bozuk, ekleme islemi basarisiz")
                self.screenQueue.put(str(anlamli_data))
            self.komsuTalepFihristi[int(self.serverID)] = list

            for i in self.komsuTalepFihristi.keys():
                for j in self.arzFihristi.keys():
                    k = 0
                    for k in range(len(self.komsuTalepFihristi[i])):
                        if (self.komsuTalepFihristi[i][k][0] == int(j)):
                            clientButce = self.arzFihristi.get(j)[5] / self.arzFihristi.get(j)[2]
                            komsuButce = self.komsuTalepFihristi.get(i)[k][6] / self.komsuTalepFihristi.get(i)[k][3]
                            if (clientButce <= komsuButce and str(self.komsuTalepFihristi.get(i)[k][4]) == str(
                                    self.arzFihristi.get(j)[3])):
                                self.writeQueue.put(
                                    "TR:A:" + str(j) + ":" + str(self.arzFihristi.get(j)[0]) + ":" + str(
                                        self.arzFihristi.get(j)[2]) + ":" + str(self.arzFihristi.get(j)[3]) + ":" + str(
                                        self.arzFihristi.get(j)[5]))
                                print("TR:A:" + str(j) + ":" + str(self.arzFihristi.get(j)[0]) + ":" + str(
                                    self.arzFihristi.get(j)[2]) + ":" + str(self.arzFihristi.get(j)[3]) + ":" + str(
                                    self.arzFihristi.get(j)[5]))

        elif dataInByte[0:2] == "OO".encode():
            list = []
            virguldenAyrilmisData = dataInByte.decode().split(",")
            for i in range(len(virguldenAyrilmisData)):
                parsedData = virguldenAyrilmisData[i].split(":")
                if parsedData[1] == "BEGIN":
                    anlamli_data = "Arzlar alinmaya baslaniyor."
                elif parsedData[1] == "END":
                    anlamli_data = "Arz alma islemi sonlandi."
                else:
                    try:
                        arz = parsedData[1:]
                        list.append(
                            [int(parsedData[1]), parsedData[2], parsedData[3], int(parsedData[4]), parsedData[5],
                             parsedData[6], int(parsedData[7])])
                        anlamli_data = str(arz)
                    except:
                        anlamli_data = (arz[0] + " arzinin yapisi bozuk, ekleme islemi basarisiz")
                self.screenQueue.put(str(anlamli_data))
            self.komsuArzFihristi[int(self.serverID)] = list

            for i in self.komsuArzFihristi.keys():
                for j in self.talepFihristi.keys():
                    k = 0
                    for k in range(len(self.komsuArzFihristi[i])):
                        if (self.komsuArzFihristi[i][k][0] == int(j)):
                            clientButce = self.talepFihristi.get(j)[5] / self.talepFihristi.get(j)[2]
                            komsuButce = self.komsuArzFihristi.get(i)[k][6] / self.komsuArzFihristi.get(i)[k][3]
                            if (clientButce <= komsuButce and str(self.komsuArzFihristi.get(i)[k][4]) == str(
                                    self.talepFihristi.get(j)[3])):
                                self.writeQueue.put(
                                    "TR:T:" + str(j) + ":" + str(self.talepFihristi.get(j)[0]) + ":" + str(
                                        self.talepFihristi.get(j)[2]) + ":" + str(
                                        self.talepFihristi.get(j)[3]) + ":" + str(self.talepFihristi.get(j)[5]))
                                print("TR:T:" + str(j) + ":" + str(self.talepFihristi.get(j)[0]) + ":" + str(
                                    self.talepFihristi.get(j)[2]) + ":" + str(self.talepFihristi.get(j)[3]) + ":" + str(
                                    self.talepFihristi.get(j)[5]))

        elif dataInByte[0:2] == "MO".encode():
            anlamli_data = "mesaj gönderildi."

        elif dataInByte[0:2] == "BO".encode():
            print(self.abonelikFihristi)
            data = dataInByte.decode()
            if data[0:3] == "BOF":
                self.abonelikFihristi[int(self.serverID)][2] = False
                anlamli_data = "Engel kaldırıldı."
            elif data[0:3] == "BOT":
                self.abonelikFihristi[int(self.serverID)][2] = True
                anlamli_data = "Engelledin."
                if (self.abonelikFihristi[int(self.serverID)][1] == True):  # onu üyelikten çıkarıyorum (1. parametre onun bana üye olması)
                    self.abonelikFihristi[int(self.serverID)][1] = False
            else:
                anlamli_data = "Engel durumu değişmedi."
            print(self.abonelikFihristi)


        elif dataInByte[0:2] == "SO".encode():


            if(self.abonelikFihristi[int(self.serverID)][1] == False or self.abonelikFihristi[int(self.serverID)][1] ==None):
                self.abonelikFihristi[int(self.serverID)][1] = True
                anlamli_data = "Uyelik oluştu."
            elif(self.abonelikFihristi[int(self.serverID)][1] == True):
                self.abonelikFihristi[int(self.serverID)][1] = False
                anlamli_data = "Uyelikten çıkarıldı."
            else:
                anlamli_data = "Uyelik durumu güncellenemedi."

        elif dataInByte[0:2] == "UO".encode():
            anlamli_data = ""

        elif dataInByte[0:2] == "UN".encode():
            anlamli_data = ""

        elif dataInByte[0:2] == "TO".encode():
            anlamli_data = ""

        elif dataInByte[0:2] == "TN".encode():
            anlamli_data = ""

        elif dataInByte[0:2] == "ER".encode():
            anlamli_data = ""

        anlamli_data = "-Server- " + anlamli_data
        return anlamli_data

    def run(self):
        while True:
            incoming_data = self.csoc.recv(1024)
            # meanful_data = self.incoming_parser(incoming_data.decode().strip())
            meanful_data = self.incoming_parser(incoming_data.strip())
            self.screenQueue.put(meanful_data)
            if incoming_data.strip()[0:2] == "BY".encode():
                print("read thread istemci BY dasın")
                break
        self.lQueue.put("Read Thread Istemci Sonlandirildi")
        self.csoc.close()


class WriteThreadIstemci(threading.Thread):
    def __init__(self, csoc, writeQueue,lQueue):
        threading.Thread.__init__(self)
        self.csoc = csoc
        self.writeQueue = writeQueue
        self.lQueue=lQueue

    def run(self):
        while True:
            if not self.writeQueue.empty():
                queueMessage = self.writeQueue.get()
                if (type(queueMessage) == str):
                    print("tip stringmiş")
                    self.csoc.send(queueMessage.encode())
                    if queueMessage.strip()[0:2] == "QU":
                        print("write thread istemci qu dasın")
                        break
                else:
                    print("tip string degilmiş")
                    self.csoc.send(queueMessage)
        self.lQueue.put("WriteThreadIstemci sonlandirildi")

        #self.csoc.close()


class ClientDialog(QMainWindow):
    def __init__(self, talepFihristi, arzFihristi, komsuArzFihristi, komsuTalepFihristi, komsuFihristi, abonelikFihristi, uuid, ip, port,
                 screenQueue,
                 sistemTipi, geoloc, nickname, my_public_key, my_private_key,lQueue):

        self.writeQueue = queue.Queue()
        self.connectedFlag = 0
        self.screenQueue = screenQueue
        self.uuid = uuid
        self.ip = ip
        self.port = port
        self.sistemTipi = sistemTipi
        self.geoloc = geoloc
        self.nickname = nickname
        self.my_public_key = my_public_key
        self.my_private_key = my_private_key
        self.talepFihristi = talepFihristi
        self.arzFihristi = arzFihristi
        self.komsuArzFihristi = komsuArzFihristi
        self.komsuTalepFihristi = komsuTalepFihristi
        self.komsuFihristi = komsuFihristi
        self.abonelikFihristi = abonelikFihristi

        self.karsiServerID={}

        self.clickedKomsuIP = None
        self.clickedKomsuPort = None  # bir komsuya tiklandiginda connect butonunun calismasi icin gereken bilgiler
        self.clickedKomsuUUID = None

        self.lQueue=lQueue




        self.qt_app = QApplication(sys.argv)
        QMainWindow.__init__(self, None)
        loadUi("arayuz.ui", self)

        self.label_kullaniciBilgisi.setText(self.nickname + " (ID: " + str(self.uuid) + ")")

        self.send_button.clicked.connect(self.outgoing_parser)
        self.pushButton_connect.clicked.connect(lambda _, s="connect": self.clickedActionButton(x=s))
        self.pushButton_connections.clicked.connect(lambda _, s="CS": self.clickedActionButton(x=s))
        self.pushButton_publicKey.clicked.connect(lambda _, s="PK": self.clickedActionButton(x=s))
        self.pushButton_demandes.clicked.connect(lambda _, s="DM": self.clickedActionButton(x=s))
        self.pushButton_offers.clicked.connect(lambda _, s="OF": self.clickedActionButton(x=s))
        self.pushButton_message.clicked.connect(lambda _, s="MS": self.clickedActionButton(x=s))
        self.pushButton_subscribe.clicked.connect(lambda _, s="SB": self.clickedActionButton(x=s))
        self.pushButton_block.clicked.connect(lambda _, s="BL": self.clickedActionButton(x=s))
        self.pushButton_quit.clicked.connect(lambda _, s="QU": self.clickedActionButton(x=s))
        self.pushButton_newdemand.clicked.connect(lambda _, s="AA": self.clickedActionButton(x=s))
        self.pushButton_newoffer.clicked.connect(lambda _, s="AB": self.clickedActionButton(x=s))

        self.timer = QTimer()
        func = functools.partial(self.updateText)
        self.timer.timeout.connect(func)
        self.timer.start(10)

        self.timerKomsuListesi = QTimer()
        func2 = functools.partial(self.updateKomsuListesi)
        self.timerKomsuListesi.timeout.connect(func2)
        self.timerKomsuListesi.start(2000)

        self.timerUI = QTimer()
        func3 = functools.partial(self.updateUI)
        self.timerUI.timeout.connect(func3)
        self.timerUI.start(10)

    def clickedActionButton(self, x):
        data = self.sender.text()
        x = str(x)
        print(x)
        if not (x == "connect" or x == "PK" or x == "SB" or x == "BL" or x == "DM" or x == "OF" or x == "QU") and data == "":
            self.screenQueue.put("Local: Lütfen gerekli parametreleri alt kısma yazdıktan sonra butonu kullanın.")
            return
        elif x == "connect":
            dataSplit = data.split(":")

            if self.clickedKomsuPort != None and self.clickedKomsuIP != None and len(dataSplit) == 0:
                ip = str(self.clickedKomsuIP)
                port = int(self.clickedKomsuPort)
            else:
                if len(dataSplit) == 2:
                    ip = str(dataSplit[0])
                    port = int(dataSplit[1])
                else:
                    self.screenQueue.put("Local: Yanlış parametre kullanımı.")
                    return

            IstTh = IstemciThread(ip, port, self.ip, self.port, self.uuid, self.sistemTipi, self.geoloc,
                                  self.nickname,
                                  self.screenQueue, self.writeQueue, self.talepFihristi, self.arzFihristi,
                                  self.my_public_key, self.my_private_key,self.komsuFihristi,self.abonelikFihristi,self.komsuArzFihristi, self.komsuTalepFihristi, self.lQueue)
            IstTh.start()
            self.connectedFlag = 1
            self.writeQueue.put("HE")

        elif x == "SB" or x == "BL" or x == "PK" or x == "QU":
            if x == "QU":
                self.connectedFlag = 0
            if x == "PK":
                x = x+":" + str(self.my_public_key.n) + ":" + str(self.my_public_key.e)
            if x == "BL":
                try:
                    if self.abonelikFihristi[int(self.clickedKomsuUUID)][2]:#bende engelli mi
                        karar = "F"
                    else:
                        karar = "T"
                    komsu_pub_key = rsa.key.PublicKey(int(self.komsuFihristi[int(self.clickedKomsuUUID)][4]),
                                                      int(self.komsuFihristi[int(self.clickedKomsuUUID)][3]))  # pubk(n,e)
                    print(karar)
                    crypted_message = rsa.encrypt(str(karar).encode(), komsu_pub_key)
                    self.writeQueue.put("BL:".encode() + crypted_message)

                except:
                    self.screenQueue.put("Bağlı olduğunuz komşuyu soldan seçiniz.")
            if x == "SB":
                try:
                    if self.abonelikFihristi[int(self.clickedKomsuUUID)][1]:  # bende ona abone miyim
                        karar = "F"
                    else:
                        karar = "T"
                    komsu_pub_key = rsa.key.PublicKey(int(self.komsuFihristi[int(self.clickedKomsuUUID)][4]),
                                                      int(self.komsuFihristi[int(self.clickedKomsuUUID)][3]))  # pubk(n,e)

                    crypted_message = rsa.encrypt(karar.encode(), komsu_pub_key)
                    self.writeQueue.put("SB:".encode() + crypted_message)
                except:
                    self.screenQueue.put("Bağlı olduğunuz komşuyu soldan seçiniz.")

            self.writeQueue.put(x)
        elif x == "CS" or x == "MS" or x == "AA" or x == "DM" or x == "OF" or x == "AB":
            if x == "MS":
                komsu_pub_key = rsa.key.PublicKey(int(self.komsuFihristi[int(self.clickedKomsuUUID)][4]),
                                                  int(self.komsuFihristi[int(self.clickedKomsuUUID)][3]))  # pubk(n,e)

                crypted_message = rsa.encrypt(str(data).encode(), komsu_pub_key)

                self.writeQueue.put("MS:".encode() + crypted_message)
            else:
                self.writeQueue.put(x+":"+data)
            print(x+":"+data)
        self.screenQueue.put("Local: " + data)


    def updateText(self):

        if not self.screenQueue.empty():
            data = self.screenQueue.get()

            t = time.localtime()
            pt = "%02d:%02d" % (t.tm_hour, t.tm_min)

            self.channel.append(pt + " " +data)
        else:
            return

    def updateUI(self):
        self.pushButton_subscribe.setText("Abone Ol/Çık")
        self.pushButton_block.setText("Engelle/En. Kaldır")

        self.pushButton_connect.setEnabled(True)
        self.pushButton_connections.setEnabled(True)
        self.pushButton_publicKey.setEnabled(True)
        self.pushButton_demandes.setEnabled(True)
        self.pushButton_offers.setEnabled(True)
        self.pushButton_message.setEnabled(True)
        self.pushButton_subscribe.setEnabled(True)
        self.pushButton_block.setEnabled(True)
        self.pushButton_quit.setEnabled(True)
        self.pushButton_newdemand.setEnabled(True)
        self.pushButton_newoffer.setEnabled(True)

    def updateKomsuListesi(self):
        kullaniciButonlari = []

        for i in reversed(range(self.KomsuListesiLayoutu.count())):
            self.KomsuListesiLayoutu.itemAt(i).widget().setParent(
                None)  # arayuzdeki komsu listesini sildik. yeniden olusturacagiz.
        sayac = 0
        for key in list(self.komsuFihristi):
            kullaniciButonlari.append(sayac)
            kullaniciButonlari[sayac] = QPushButton(self.komsuFihristi[key][6])
            kullaniciButonlari[sayac].clicked.connect(lambda _, s=key: self.clickedKomsuButonu(x=s))
            self.KomsuListesiLayoutu.addWidget(kullaniciButonlari[sayac])
            sayac = sayac + 1

    def clickedKomsuButonu(self, x):
        self.clickedKomsuIP = self.komsuFihristi[x][0]
        self.clickedKomsuPort = self.komsuFihristi[x][1]
        self.clickedKomsuUUID = x

    def outgoing_parser(self):

        data = self.sender.text()
        self.screenQueue.put("Local: " + data)

        #komsu_pub_key = rsa.key.PublicKey(int(self.komsuFihristi[self.clickedKomsuUUID][4]), int(self.komsuFihristi[self.clickedKomsuUUID][3]))  # pubk(n,e)
        #print(komsu_pub_key)
        if len(data) == 0:
            return
        if data[0] == "/":

            dataSplitted = data.replace("/", "").split((":"))
            command = dataSplitted[0]

            if command == "connect":  # Bir peer'a /connect:ip:port seklinde baglanmak
                ip = dataSplitted[1]
                ip = str(ip)

                port = dataSplitted[2]


                kuuid = dataSplitted[3]

                IstemciQueue=queue.Queue()


                """komsuFihristi[int(parsedData[1])] = [parsedData[2], parsedData[3], parsedData[4], parsedData[5],
                                                     parsedData[6], parsedData[7], parsedData[8], parsedData[9]]"""
                IstTh = IstemciThread(ip, port, self.ip, self.port, self.uuid, self.sistemTipi, self.geoloc,
                                      self.nickname, self.screenQueue, self.writeQueue, self.talepFihristi,
                                      self.arzFihristi,  self.my_private_key, self.my_private_key,
                                      self.komsuFihristi,self.abonelikFihristi,self.komsuArzFihristi,self.komsuTalepFihristi,self.lQueue)
                self.lQueue.put(str(ip))
                self.lQueue.put("adli ip ile baglanti kuruldu")
                """IstTh = IstemciThread(ip, port, self.ip, self.port, self.uuid, self.sistemTipi, self.geoloc,
                                      self.nickname, self.screenQueue, IstemciQueue, self.talepFihristi,
                                      self.arzFihristi, self.my_private_key, self.my_private_key,
                                      self.komsuFihristi, self.abonelikFihristi, self.komsuArzFihristi,
                                      self.komsuTalepFihristi)"""
                IstTh.start()

                self.clickedKomsuPort = port
                self.clickedKomsuIP = ip
                self.clickedKomsuUUID = kuuid

                self.connectedFlag = 1

                self.writeQueue.put("HE")
            elif command == "quit" and self.connectedFlag == 1:
                self.connectedFlag = 0
                self.writeQueue.put("QU")
            elif command == "connections" and self.connectedFlag == 1:

                num = dataSplitted[1]
                self.writeQueue.put("BEGIN:" + num)
            elif command == "publicKey" and self.connectedFlag == 1:
                self.writeQueue.put(dataSplitted.replace("/publicKey", "PK"))
            elif command == "demandes" and self.connectedFlag == 1:
                komsu_pub_key = rsa.key.PublicKey(int(self.komsuFihristi[int(self.clickedKomsuUUID)][4]),
                                                  int(self.komsuFihristi[int(self.clickedKomsuUUID)][3]))  # pubk(n,e)
                safData = data.split(":", 1)
                crypted_m = rsa.encrypt(str(safData[1]).encode(), komsu_pub_key)
                cyrpted_message = "DM".encode() + ":".encode() + crypted_m
                self.writeQueue.put(cyrpted_message) # TODO: DEMANDES ILE BU TARAFIN DEMANDE LISTESINI GONDER

            elif command == "offers" and self.connectedFlag == 1:
                komsu_pub_key = rsa.key.PublicKey(int(self.komsuFihristi[int(self.clickedKomsuUUID)][4]),
                                                  int(self.komsuFihristi[int(self.clickedKomsuUUID)][3]))  # pubk(n,e)
                safData = data.split(":", 1)
                crypted_m = rsa.encrypt(str(safData[1]).encode(), komsu_pub_key)
                cyrpted_message = "OF".encode() + ":".encode() + crypted_m
                self.writeQueue.put(cyrpted_message) # TODO: OFFERS ILE BU TARAFIN OFFERS LISTESINI GONDER

            elif command == "message" and self.connectedFlag == 1:

                komsu_pub_key = rsa.key.PublicKey(int(self.komsuFihristi[int(self.clickedKomsuUUID)][4]),
                                                  int(self.komsuFihristi[int(self.clickedKomsuUUID)][3]))  # pubk(n,e)

                crypted_message = rsa.encrypt(str(dataSplitted[1]).encode(), komsu_pub_key)

                self.writeQueue.put("MS:".encode() + crypted_message)
                print("mesaj gönderildiiii")

            elif command == "block" and self.connectedFlag == 1:
                komsu_pub_key = rsa.key.PublicKey(int(self.komsuFihristi[int(self.clickedKomsuUUID)][4]),
                                                  int(self.komsuFihristi[int(self.clickedKomsuUUID)][3]))  # pubk(n,e)

                crypted_message = rsa.encrypt(str(dataSplitted[1]).encode(), komsu_pub_key)
                print("mesaj crypto")
                self.writeQueue.put("BL:".encode() + crypted_message)
            elif command == "subscribe" and self.connectedFlag == 1:
                komsu_pub_key = rsa.key.PublicKey(int(self.komsuFihristi[int(self.clickedKomsuUUID)][4]),
                                                  int(self.komsuFihristi[int(self.clickedKomsuUUID)][3]))  # pubk(n,e)

                crypted_message = rsa.encrypt(str(dataSplitted[1]).encode(), komsu_pub_key)
                print("mesaj crypto")
                self.writeQueue.put("SB:".encode() + crypted_message)

            elif command == "newdemand" and self.connectedFlag == 1:   #arz
                self.writeQueue.put(data.replace("/newdemand", "AA"))  # yanitleri A0 (olumlu), A1
            elif command == "newoffer" and self.connectedFlag == 1:    #talep gönderme
                self.writeQueue.put(data.replace("/newoffer", "AB"))  # yanitleri A2 (olumlu), A3
            else:
                if self.connectedFlag == 1:
                    self.screenQueue.put("Local: Command Error.")
                else:
                    self.screenQueue.put("Giris yapilmali")
        else:
            self.screenQueue.put("Komutlar '/' ile baslamalidir.")

        self.sender.clear()

    def run(self):
        self.show()
        self.qt_app.exec_()


class IstemciThread(threading.Thread):
    def __init__(self, ip, port, selfIP, selfPORT, uuid, sistemTipi, geoloc, nickname, screenQueue, writeQueue,
                 talepFihristi,
                 arzFihristi, my_public_key, my_private_key,komsuFihristi,abonelikFihristi,komsuArzFihristi,komsuTalepFihristi,lQueue):
        threading.Thread.__init__(self)

        self.ScreenQueue = screenQueue
        self.WriteQueue = writeQueue
        self.sistemTipi = sistemTipi
        self.geoloc = geoloc
        self.nickname = nickname
        self.ip = ip
        self.port = int(port)
        self.selfIP = selfIP
        self.selfPORT = selfPORT
        self.uuid = uuid
        self.my_public_key = my_public_key
        self.my_private_key = my_private_key
        self.talepFihristi = talepFihristi
        self.arzFihristi = arzFihristi
        self.komsuFihristi = komsuFihristi
        self.komsuArzFihristi = komsuArzFihristi
        self.komsuTalepFihristi = komsuTalepFihristi
        self.abonelikFihristi = abonelikFihristi
        self.lQueue=lQueue


    def run(self):
        s1 = socket.socket()
        s1.connect((self.ip, self.port))
        metin = str("Connected to server with Peer Ip = " + str(self.ip) + " and Port = " + str(self.port))
        self.lQueue.put((metin))

        wtIstemci = WriteThreadIstemci(s1, self.WriteQueue,self.lQueue)
        rtIstemci = ReadThreadIstemci(s1, self.WriteQueue, self.ScreenQueue, self.uuid, self.ip, self.port, self.selfIP,
                                      self.selfPORT, self.sistemTipi, self.geoloc, self.nickname, self.my_public_key,
                                      self.my_private_key, self.arzFihristi, self.talepFihristi, self.komsuFihristi,self.abonelikFihristi,self.komsuArzFihristi, self.komsuTalepFihristi,self.lQueue)

        wtIstemci.start()
        rtIstemci.start()


class WriteThreadServer(threading.Thread):
    def __init__(self, csoc, address, threadQueue,lQueue):
        threading.Thread.__init__(self)
        self.csoc = csoc
        self.address = address
        self.tqueue = threadQueue
        self.lQueue=lQueue

    def run(self):
        while True:
            queueMessage = self.tqueue.get()
            self.csoc.send((queueMessage + '\n').encode())
            if queueMessage[0:2] == "BY":
                break
        self.csoc.close()


class ReadThreadServer(threading.Thread):
    def __init__(self, uuid,host,port, csoc, address, screenQueue, threadQueue, komsuFihristi, abonelikFihristi, talepFihristi, arzFihristi, komsuArzFihristi, komsuTalepFihristi, my_public_key,
                 my_private_key,lQueue):
        threading.Thread.__init__(self)
        # self.name = name
        self.uuid = uuid
        self.nickname = None
        self.csoc = csoc
        self.address = address
        self.tQueue = threadQueue
        self.komsuFihristi = komsuFihristi
        self.komsuArzFihristi = komsuArzFihristi
        self.abonelikFihristi = abonelikFihristi
        self.komsuTalepFihristi = komsuTalepFihristi
        self.talepFihristi = talepFihristi
        self.arzFihristi = arzFihristi
        self.my_public_Key = my_public_key
        self.my_private_key = my_private_key
        self.host = host
        self.port = port
        self.istemciID = 0
        self.istemciDurum = False
        self.screenQueue = screenQueue
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
        self.lQueue=lQueue

    def parser(self, dataInByte):
        # def parser(self, data):

        # parsedData = data.split(":")

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
                if (self.abonelikFihristi[int(self.istemciID)][2] == True):  # Kisi listesinde var ve engelli mi?
                    self.tQueue.put(data.replace("RG", "RN"))
                else:  # Kisi listesinde var ve engelli degil mi?
                    self.istemciDurum = True
                    self.tQueue.put(data.replace("RG", "RO"))
            else:  # Kisi listesinde yok mu?
                self.tQueue.put(data.replace("RG", "RNN"))  # kisi listesinde yok ama ekleniyo ?
        elif dataInByte[0:3] == "END".encode():
            self.tQueue.put("END")

        elif dataInByte[0:5] == "BEGIN".encode():
            if (self.abonelikFihristi[int(self.istemciID)][2] == True):
                self.tQueue.put("RN")
            else:
                self.tQueue.put(dataInByte.decode())

        # elif parsedData[0] == "IG":
        elif dataInByte[0:2] == "IG".encode():
            data = dataInByte.decode()

            parsedData = dataInByte.decode().split(":")
            if(len(parsedData)>1):
                self.uuid2 = parsedData[1]
                if int(self.uuid1) == int(self.uuid2):
                    print("olduuu")
                    self.istemciDurum = True
                    self.istemciID=int(self.uuid1)
                    self.abonelikFihristi[int(self.istemciID)]=[None,None,None,None]         # 1. value: abone_mi
                                                                                        # 2. value: ben_ona_abone_mi
                                                                                        # 3. value: bende_engellemi(self.komsuFihristi[int(self.kullanici_uuid)][5])
                                                                                        # 4. value: ben_onda_engellimi

                    self.komsuFihristi[int(parsedData[1])]=[parsedData[2], parsedData[3], parsedData[4], parsedData[5],
                                                           parsedData[6], parsedData[7],parsedData[8],parsedData[9] ]
                    self.kisi_var_mi=True
                    self.tQueue.put("OG:" + str(self.uuid))
                else:
                    self.tQueue.put("RN")
            elif(len(parsedData)==1):
                self.tQueue.put("OG" +str(self.uuid))
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
            if (self.abonelikFihristi[int(self.istemciID)][2] == True):
                self.tQueue.put("RN")
            else:

                self.tQueue.put("PK:" + str(self.my_public_Key.n) + ":" + str(self.my_public_Key.e)) # pubk (n,e)
                if parsedData[1] != None or parsedData[2] != None:
                    self.kullanici_publickey = rsa.key.PublicKey(int(parsedData[1]), int(parsedData[2]))
                else:
                    self.kullanici_publickey = None
                    self.tQueue.put("PN")

        # elif parsedData[0] == "PT" and self.istemciDurum == True:
        elif dataInByte[0:2] == "PT".encode() and self.istemciDurum == True:

            sifreliMetin = dataInByte[3:].strip()
            print(self.komsuFihristi)

            if (self.abonelikFihristi[int(self.istemciID)][2] == True):
                self.tQueue.put("RN")
            else:
                decrypt_uuid = rsa.decrypt(sifreliMetin, self.my_private_key)
                if int(self.uuid) == int(decrypt_uuid.decode()):
                    if self.kullanici_publickey == None:
                        self.tQueue.put("PO")
                    else:
                        encrypt_kullanici_uuid = rsa.encrypt(str(self.istemciID).encode(),self.kullanici_publickey)
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
            if (self.abonelikFihristi[int(self.istemciID)][2] == True):
                self.tQueue.put("RN")
            else:
                # self.tQueue.put("CO:BEGIN")
                for i in self.komsuFihristi:
                    if (self.komsuFihristi[i][5] == geoloc):
                        list.append(str("CO:" + str(i) + ":" + str(self.komsuFihristi[i][0]) + ":" + str(
                            self.komsuFihristi[i][1]) + ":" + str(self.komsuFihristi[i][2]) + ":" + str(
                            self.komsuFihristi[i][3]) + ":" + str(self.komsuFihristi[i][4]) + ":" + str(self.komsuFihristi[i][5]) + ":" + str(self.komsuFihristi[i][6] + ":" + str(self.komsuFihristi[i][7]))))

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

        # elif parsedData[0] == "MS" and self.istemciDurum == True:
        elif dataInByte[0:2] == "MS".encode() and self.istemciDurum == True:
            sifreliMetin = dataInByte[3:].strip()

            if (self.abonelikFihristi[int(self.istemciID)][2] == True):
                self.tQueue.put("RN")
            else:
                decrypt_message = rsa.decrypt(sifreliMetin, self.my_private_key)
                self.screenQueue.put(decrypt_message.decode())
                self.tQueue.put("MO")








            """data = dataInByte.decode()
            parsedData = data.split(":")
            print(self.komsuFihristi)

            if (self.abonelikFihristi[int(self.istemciID)][2] == True or  self.abonelikFihristi[int(self.istemciID)][3] == True):
                self.tQueue.put("RN")
            # elif (): #publicKeyFihristi:{key,uid,value,publickey}
            # self.tQueue.put("PN")                                        #oldugunu dusunurek kontrol yapildi)
            else:
                self.screenQueue.put(parsedData[1])
                self.tQueue.put("MO")"""


        # elif data[0:2] == "BL" and self.istemciDurum == True:
        elif dataInByte[0:2] == "BL".encode() and self.istemciDurum == True:
            sifreliMetin = dataInByte[3:].strip()
            decrypt_message = rsa.decrypt(sifreliMetin, self.my_private_key)
            if (decrypt_message.decode() == "T" and self.abonelikFihristi[self.istemciID][3] != True):  # kişinin engellenmesi
                self.abonelikFihristi[self.istemciID][3] = True  # abonelik Fihristindeki engelli olma durumunu güncellemek için kullanılır
                self.tQueue.put("BOT")
                if (self.abonelikFihristi[self.istemciID][0] == True):  # onun üyeğinden çıkıyorum (0. parametre onun bana üye olması
                    self.abonelikFihristi[self.istemciID][0] = False
                    print("engellendin")
            elif decrypt_message.decode() == "T" and self.abonelikFihristi[self.istemciID][3] == True:  # kişi engelli olduğu halde engellenmesi
                self.tQueue.put("RNBT")
            elif (decrypt_message.decode() == "F" and self.abonelikFihristi[self.istemciID][3] == True):  # kişinin engelinin kaldırılması
                self.abonelikFihristi[self.istemciID][3] = False
                self.tQueue.put("BOF")
                print("engelin kaldırıldı")
            elif decrypt_message.decode() == "F" and self.abonelikFihristi[self.istemciID][3] == None:  # kişi engellenmeden engelin kaldırılma durumu
                self.tQueue.put("RNBB")
            elif decrypt_message.decode() == "F" and self.abonelikFihristi[self.istemciID][3] == False:  # kişinin engeli kaldırıldığı halde engelin kaldırılma istği gelmesi
                self.tQueue.put("RNBF")
            else:
                print("pass tayım")
                pass
            print(self.abonelikFihristi)
        # elif data[0:2] == "SB" and self.istemciDurum == True:
        elif dataInByte[0:2] == "SB".encode() and self.istemciDurum == True:
            sifreliMetin = dataInByte[3:].strip()
            decrypt_message = rsa.decrypt(sifreliMetin, self.my_private_key)
            if self.abonelikFihristi[int(self.istemciID)][2] == True:
                self.tQueue.put("RN")
            #   elif (self.publicKeyFihristi[i][3] == self.kullanici_publickey):
            #      self.tQueue.put("PN")
            else:
                if (decrypt_message.decode() == "T" and self.abonelikFihristi[int(self.istemciID)][0]!=True):  # üye olma durumu, kaynakta gelen mesaj: SB:{T}
                    self.abonelikFihristi[int(self.istemciID)][0] = True
                    print(str(self.istemciID) + ":  eklendi")
                    self.tQueue.put("SO")
                elif(decrypt_message.decode() == "T" and self.abonelikFihristi[int(self.istemciID)][0]==True):
                    self.tQueue.put("RNUT")
                elif (decrypt_message.decode() == "F" and self.abonelikFihristi[int(self.istemciID)][0] == True):  # üyelikten cıkma durumu, kaynakta gelen mesaj: SB:{F}
                    # üye olmadan üyelikten çıkılmaz kontrolü yapılıyor
                    self.abonelikFihristi[int(self.istemciID)][0] = False
                    self.tQueue.put("SO")
                    print(str(self.istemciID) + ":  cıktı")
                elif (decrypt_message.decode() == "F" and self.abonelikFihristi[int(self.istemciID)][0] == False):
                    self.tQueue.put("RNUF")
                elif (decrypt_message.decode() == "F" and self.abonelikFihristi[int(self.istemciID)][0] == None):
                    self.tQueue.put("RNUO")
                else:
                    pass  # yanlis parametre verilmis, komut hatasi mesaji geri gitsin (ER
                print(self.abonelikFihristi)

        # elif data[0:2] == "QU":
        elif dataInByte[0:2] == "QU".encode() and self.istemciDurum == True:
            data = dataInByte.decode()
            parsedData = dataInByte.decode().split(":")
            self.tQueue.put("BY")

        elif dataInByte[0:2] == "DM".encode():
            sifreliMetin = dataInByte[3:]
            decrypt_message = rsa.decrypt(sifreliMetin, self.my_private_key)
            data = decrypt_message.decode()
            parsedData = data.split(":")

            if self.abonelikFihristi[int(self.istemciID)][2] == True:
                self.tQueue.put("RN")
            elif parsedData[0] == "N":
                kayitSayisi = parsedData[1]
                kayitSayisi = int(kayitSayisi)
                if kayitSayisi > len(self.talepFihristi):
                    kayitSayisi = len(self.talepFihristi)
                gonderArray = []
                gonderArray.append("DO:BEGIN")
                counter = 0
                for i in self.talepFihristi:
                    gonderArray.append(
                        "DO:" + str(i) + ":" + str(self.talepFihristi[i][0]) + ":" + str(self.talepFihristi[i][1]) + ":"
                        + str(self.talepFihristi[i][2]) + ":" + str(self.talepFihristi[i][3]) + ":" +
                        str(self.talepFihristi[i][4]) + ":" + str(self.talepFihristi[i][5]))
                    counter=counter+1
                    if counter == kayitSayisi:
                        break
                gonderArray.append("DO:END")
                gonderString = ""
                for i in range(len(gonderArray)):
                    if gonderArray[i] != "DO:END":
                        gonderString = gonderString + gonderArray[i]+","
                    else:
                        gonderString = gonderString + gonderArray[i]
                self.tQueue.put(gonderString)
            elif parsedData[0] == "K":
                # kullanım: talepFihristi[talep uid] = [talep adı, talep birimi, talep miktarı, karşılık adı, karşılık birimi, azami(max) karşılık miktarı]
                keyword = parsedData[1]
                gonderArray = []
                gonderArray.append("DO:BEGIN")
                for i in self.talepFihristi:
                    if keyword == self.talepFihristi[i][0]:
                        gonderArray.append("DO:"+ str(i) + ":" +str(self.talepFihristi[i][0]) + ":" + str(self.talepFihristi[i][1]) + ":"
                                        + str(self.talepFihristi[i][2])+ ":" + str(self.talepFihristi[i][3])+ ":" +
                                        str(self.talepFihristi[i][4])+ ":" + str(self.talepFihristi[i][5]))
                gonderArray.append("DO:END")
                gonderString = ""
                for i in range(len(gonderArray)):
                    if gonderArray[i] != "DO:END":
                        gonderString = gonderString + gonderArray[i] + ","
                    else:
                        gonderString = gonderString + gonderArray[i]
                self.tQueue.put(gonderString)
            else:
                self.tQueue.put("RN")



        elif dataInByte[0:2] == "TR".encode():

            type = dataInByte.decode().split(":")[1]

            uuid = dataInByte.decode().split(":")[2]

            clientFiyat = int(dataInByte.decode().split(":")[6]) / int(dataInByte.decode().split(":")[4])

            if (type == "A"):

                serverTalepFiyat = int(self.talepFihristi.get(int(uuid))[5]) / int(self.talepFihristi.get(int(uuid))[2])

                if (clientFiyat >= serverTalepFiyat):

                    clientAdet = dataInByte.decode().split(":")[4]

                    serverAdet = self.talepFihristi.get((int(uuid)))[2]

                    if (float(clientAdet) >= float(serverAdet)):

                        del self.talepFihristi[int(uuid)]

                        print(self.talepFihristi)

                    else:

                        serverAdet = float(serverAdet) - float(clientAdet)

                        self.talepFihristi.get(int(uuid))[2] = serverAdet

                        self.talepFihristi.get(int(uuid))[5] = serverTalepFiyat * serverAdet

                        print(self.talepFihristi)

                    self.tQueue.put(str(dataInByte.decode()).replace("TR:", "TO:"))

                else:

                    self.tQueue.put("TN")

            if (type == "T"):

                serverArzFiyat = int(self.arzFihristi.get((int(uuid)))[5]) / int(self.arzFihristi.get((int(uuid)))[2])

                if (clientFiyat >= serverArzFiyat):

                    clientAdet = dataInByte.decode().split(":")[4]

                    serverAdet = self.arzFihristi.get((int(uuid)))[2]

                    if (float(clientAdet) <= float(serverAdet)):

                        del self.arzFihristi[int(uuid)]

                    else:

                        serverAdet = float(serverAdet) - float(clientAdet)

                        self.arzFihristi.get(int(uuid))[2] = float(serverAdet)

                        self.arzFihristi.get(int(uuid))[5] = float(serverArzFiyat) * float(serverAdet)

                    self.tQueue.put(str(dataInByte.decode()).replace("TR:", "TO:"))

                else:

                    self.tQueue.put("TN")



        elif dataInByte[0:2] == "OF".encode():
            sifreliMetin = dataInByte[3:]
            decrypt_message = rsa.decrypt(sifreliMetin, self.my_private_key)
            data = decrypt_message.decode()
            parsedData = data.split(":")
            if self.abonelikFihristi[int(self.istemciID)][2] == True:
                self.tQueue.put("RN")
            elif parsedData[0] == "N":
                kayitSayisi = parsedData[1]
                kayitSayisi = int(kayitSayisi)
                if kayitSayisi > len(self.arzFihristi):
                    kayitSayisi = len(self.arzFihristi)
                gonderArray = []
                gonderArray.append("OO:BEGIN")
                counter = 0
                for i in self.arzFihristi:
                    gonderArray.append("OO:" + str(i) + ":" + str(self.arzFihristi[i][0]) + ":" + str(self.arzFihristi[i][1]) + ":"
                        + str(self.arzFihristi[i][2]) + ":" + str(self.arzFihristi[i][3]) + ":" +
                        str(self.arzFihristi[i][4]) + ":" + str(self.arzFihristi[i][5]))
                    counter=counter+1
                    if counter == kayitSayisi:
                        break
                gonderArray.append("OO:END")
                gonderString = ""
                for i in range(len(gonderArray)):
                    if gonderArray[i] != "OO:END":
                        gonderString = gonderString + gonderArray[i] + ","
                    else:
                        gonderString = gonderString + gonderArray[i]
                self.tQueue.put(gonderString)
            elif parsedData[0] == "K":
                # kullanım: arzFihristi[talep uid] = [arz adı, arz birimi, arz miktarı, karşılık adı, karşılık birimi, azami(max) karşılık miktarı]
                keyword = parsedData[1]
                gonderArray = []
                gonderArray.append("OO:BEGIN")
                for i in self.arzFihristi:
                    if keyword == self.arzFihristi[i][0]:
                        gonderArray.append("OO:" + str(i) + ":" + str(self.arzFihristi[i][0]) + ":" + str(self.arzFihristi[i][1]) + ":"
                                        + str(self.arzFihristi[i][2]) + ":" + str(self.arzFihristi[i][3]) + ":" +
                                        str(self.arzFihristi[i][4]) + ":" + str(self.arzFihristi[i][5]))
                gonderArray.append("OO:END")
                gonderString = ""
                for i in range(len(gonderArray)):
                    if gonderArray[i] != "OO:END":
                        gonderString = gonderString + gonderArray[i] + ","
                    else:
                        gonderString = gonderString + gonderArray[i]
                self.tQueue.put(gonderString)
            else:
                self.tQueue.put("RN")
        else:
            self.tQueue.put("ER")

    def run(self):
        while True:
            incoming_data = self.csoc.recv(1024)
            self.parser(incoming_data.strip())
            if (incoming_data.strip()[0:2] == "QU".encode()):
                print("read thread server QU dasın ")
                break

        self.lQueue.put("Read thread server sonlandirildi ")




class ServerThread(threading.Thread):
    def __init__(self, uuid, ip, port, screenQueue, talepFihristi, arzFihristi, komsuArzFihristi, komsuTalepFihristi, komsuFihristi,
                 abonelikFihristi, my_public_key, my_private_key,lQueue):
        threading.Thread.__init__(self)
        self.talepFihristi = talepFihristi
        self.arzFihristi = arzFihristi
        self.komsuArzFihristi = komsuArzFihristi
        self.komsuFihristi = komsuFihristi
        self.komsuTalepFihristi = komsuTalepFihristi
        self.abonelikFihristi = abonelikFihristi
        self.s = socket.socket()
        self.screenQueue = screenQueue
        self.ip = ip
        self.port = int(port)
        self.my_public_key = my_public_key
        self.my_private_key = my_private_key
        self.s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR,
                          1)  # bunu port'u tekrar kullanabilmek için yazdım. yoksa OS boşaltana kadar bayağı bekliyorsunuz serverı başlatırken.
        self.s.bind((self.ip, self.port))
        self.s.listen()
        self.uuid = uuid
        self.lQueue=lQueue
    def run(self):
        while True:
            c, addr = self.s.accept()
            self.lQueue.put(addr)
            self.lQueue.put("yeni baglanti eklendi ")

            # fakat tqueue, write thread ve read thread her kullanıcı için unique olmalı. bu yüzden onları burada yaratıp başlatıyoruz.

            yeniThreadQueue = queue.Queue()

            yeniWriteThreadServer = WriteThreadServer(c, addr, yeniThreadQueue,self.lQueue)
            yeniReadThreadServer = ReadThreadServer(self.uuid,self.ip , self.port,c, addr, self.screenQueue, yeniThreadQueue,
                                                    self.komsuFihristi, self.abonelikFihristi, self.talepFihristi, self.arzFihristi, self.komsuArzFihristi, self.komsuTalepFihristi,
                                                    self.my_public_key, self.my_private_key,self.lQueue)

            yeniWriteThreadServer.start()
            yeniReadThreadServer.start()


def main():
    fname = "logTXT.txt"




    lQueue = queue.Queue()
    l = LogThread(lQueue, fname)
    l.start()

    uuid = 10
    # port range= 1025 47808/
    # buradadaki degiskenler grub uyeleri kendileri manuel olarak degistirmeli kendine uyarliyip simulasion yapabilmek icin
    host = "0.0.0.0"
    port = 3000
    sistemTipi = 'A'
    geoloc = "kordinat"
    kullaniciAdi = "A"

    # Public / Private Key tanımlamaları
    (my_public_key, my_private_key) = rsa.newkeys(256)

    # tutacağımız data.
    talepFihristi = {
        103: ["Ayva", "KG", 3, "para", "TL", 15],
        104: ["Armut", "KG", 4, "elma", "kg", 5],
        105: ["Uzum", "KG", 6, "para", "TL", 25]
    }  # talepler her sistem için 1 tane olacaktır. istemci bazında olmayacaktır.
    # kullanım: talepFihristi[talep uid] = [talep adı, talep birimi, talep miktarı, karşılık adı, karşılık birimi, azami(max) karşılık miktarı]
    arzFihristi = {
        102: ["Karpuz", "KG", 3, "para", "TL", 15], # 5
        106: ["Sabun", "LT", 3, "para", "TL", 15], # 5
        107: ["Seftali", "KG", 4, "elma", "kg", 5],
        108: ["Nektari", "KG", 6, "para", "TL", 25]
    }  # arzlar her sistem için 1 tane olacaktır. istemci bazında olmayacaktır.
    # kullanım: arzFihristi[arz uid] = [arz adı, arz birimi, arz miktarı, karşılık adı, karşılık birimi, asgari(min) karşılık miktarı]
    komsuTalepFihristi = {}  # diğer sistemlerin talep listesi burada toplu şekilde tutulacaktır. sistemin kendi arz/talep fihristleriyle aynı yapıda yapalım ki
    # bir karmaşa olmasın. böylece karşılaştırma yaparken kodlaması daha kolay olur. ayrıca bunlar güncel olmayabilir. bir sistemin bir
    # komşusunun listesi değişmiş olabilir. bu fihrist için ilgili öğrenci bir güncelleme fonksiyonu yazmalıdır. zaman ayarlı güncelleme olabilir.
    komsuArzFihristi = {}  # komsuTalepFihristi ile aynı şeyler bunun için de geçerlidir.
    komsuFihristi = { 3: ["0.0.0.0", 2266, None, 8, 9, "kordinat", "Mert", "A"],
                      4: ["0.0.0.0", 2267, None, 10, 11, "kordinat", "Süheyla", "A"],
                      1: ["0.0.0.0", 2268,None, 12, 13, "kordinat", "Beyza", "A"]}

    # ev sistemi tanıdığı başka evleri bu fihristte tutacaktır.
    # kullanım: komsuFihristi[komsuUid] = [ip ve port, en son kontrol zamanı, public key, gps koordinatları, tanıtıcı mesaj, cinsi(A/B), tanışıklık durumu]
    # bu bilgilerin selamlaşma ve tanışma aşamasında güncelleneceği ilgili öğrenci tarafından unutulmamalıdır.
    # burada üyelik parametresini koymadım. hocanın örneğinde değişikliğe gidiyoruz. abonelik sistemini başka şekilde tutacağız sistemi yormamak için
    # ayrıca tanışıklık durumu diye bir parametre koydum. hoca derste tanışıklığın 0-1-2 diye 3 aşamadan oluşacağını, bu durumların da tutulması
    # gerektiğini söylemişti. bu parametresi 2 olan, yani bütün tanışıklık adımlarını tamamlayan kullanıcıyla ancak alışveriş başlatılabilir.
    # alışverişle ilgili öğrenci bu hususu unutmasın.

    abonelikFihristi = { 3: [True, True, True, True],
                         4: [False, False, False, False],
                         1: [True, True, True, True]}  # bu dictte sistem kendine abone olan ve kendinin abone olduğu komşularını tutacaktır.
    # kullanımı: abonelikFihristi[komsuUid] = [bana abone mi? (bool), ben ona abone miyim? (bool), bende engelli mi?, ben onda engelli miyim?]
    # bu sistemle hem her abonelik işleminde komsuArzFihristi'ni taramamış olacağız, hem aboneleri ve abone olunanları tek fihristte
    # tutacağız hem de aynı anda karşılıklı abonelik durumunda aynı kullanıcıya ait 2 data yaratmamış olacağız. ayrıca
    # burada da identifier komsuUid olduğunu kaçırmamak gerekir. bunun sayesinde kolayca komsuFihristi'ne de o kullanıcı icin ulaşılabilecek
    # ve işlem yapılabilecektir. en azından ben böyle düşündüm.
    screenQueue = queue.Queue()
    serverth = ServerThread(uuid, host, port, screenQueue, talepFihristi, arzFihristi, komsuArzFihristi, komsuTalepFihristi, komsuFihristi,
                            abonelikFihristi, my_public_key, my_private_key,lQueue)
    lQueue.put("Peer server kismi baslatildi")
    serverth.start()
    app = ClientDialog(talepFihristi, arzFihristi, komsuArzFihristi, komsuTalepFihristi, komsuFihristi, abonelikFihristi, uuid, host, port,
                       screenQueue,
                       sistemTipi, geoloc, kullaniciAdi, my_public_key, my_private_key,lQueue)
    lQueue.put(("Arayuz baslatildi"))

    app.run()


if __name__ == "__main__":
    main()


