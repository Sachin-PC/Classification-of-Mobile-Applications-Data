#!/usr/bin/env python
# coding: utf-8


import pyshark
from kamene.all import *
import xlwt 
from xlwt import Workbook 


packets = rdpcap('/home/HDUSER/Documents/SAT/Pcap_Files/Msg_watsapp_24_student9.pcap')



wb = Workbook() 
# add_sheet is used to create sheet. 
sheet1 = wb.add_sheet('Sheet 1') 

print(len(packets))
sheet1.write(0, 1, 'TIME')
sheet1.write(0, 2, 'PACKET LENGTH') 
sheet1.write(0, 3, 'PACKET SRC') 
sheet1.write(0, 4, 'PACKET DST')
sheet1.write(0, 5, 'SRC PORT NO')
sheet1.write(0, 6, 'DST PORT NO')
sheet1.write(0, 7, 'PROTOCOL') 
sheet1.write(0, 8, 'SYN')
sheet1.write(0, 9, 'FIN')
sheet1.write(0, 10,'STREAM NO')
sheet1.write(0, 11,'INBOUND')
sheet1.write(0, 12,'OUTBOUND')


packets[0].flags
FIN = 0x01
SYN = 0x02
RST = 0x04
PSH = 0x08
ACK = 0x10
URG = 0x20
ECE = 0x40
CWR = 0x80


i=1;
for packet in packets:
    time = packet['IP'].time
    src = packet['IP'].src
    dst = packet['IP'].dst
    src_port = packet['IP'].sport
    dst_port = packet['IP'].dport
    pck_len = packet['IP'].len
    proto = packet.proto
    if src == "10.8.0.1":
        sheet1.write(i,12,'1')
    else:
        sheet1.write(i,11,'1')
    if TCP in packet:
        flag = packet['TCP'].flags
        if flag & FIN:
            sheet1.write(i,9,1)
        if flag & SYN:
            sheet1.write(i,8,1)
    else:
        flag = 0;
    sheet1.write(i, 1, time)
    sheet1.write(i, 2, pck_len)
    sheet1.write(i, 3, src)
    sheet1.write(i, 4, dst)
    sheet1.write(i, 5, src_port)
    sheet1.write(i, 6, dst_port)
    sheet1.write(i, 7, proto)
    i= i+1


src_ip = []
dst_ip = []
stream_no = []
stream_fin = []
k=0
i=1
flag = 0
sn=0
temp_sn=0
index=0
for packet in packets:
    flag=0
    is_del=0;
    is_setfin = 0;
    if "TCP" in packet:
        F = packet['TCP'].flags
        src = packet['IP'].src
        dst = packet['IP'].dst
        length = len(src_ip)
        if F & RST or F & FIN or F & SYN:
            if F & RST:
                for k in range(len(src_ip)):
                    if src_ip[k] == src and dst_ip[k] == dst:
                        del src_ip[k]
                        del dst_ip[k]
                        del stream_no[k]
                        del stream_fin[k]
                        break
                    elif src_ip[k] == dst and dst_ip[k] == src:
                        del src_ip[k]
                        del dst_ip[k]
                        del stream_no[k]
                        del stream_fin[k]
                        break
                for k in range(len(src_ip)):
                    if src_ip[k] == src and dst_ip[k] == dst:
                        del src_ip[k]
                        del dst_ip[k]
                        del stream_no[k]
                        del stream_fin[k]
                        break
                    elif src_ip[k] == dst and dst_ip[k] == src:
                        del src_ip[k]
                        del dst_ip[k]
                        del stream_no[k]
                        del stream_fin[k]
                        break
            if F & SYN:
                x=0
                if length == 0:
                    src_ip.append(src)
                    dst_ip.append(dst)
                    stream_no.append(sn)
                    stream_fin.append(0)
                    sheet1.write(i,10,sn)
                    sn = sn +1
                else:
                    for k in range(length):
                        if src_ip[k] == dst and dst_ip[k] == src:
                            if stream_fin[k] == 0:
                                flag = 1
                                index = k
                                break
                            else:
                                flag = 2
                                index = k
                                break            
                        elif src_ip[k] == src and dst_ip[k] == dst:
                                flag = 3
                                index = k
                                break
                    if flag == 0:
                        src_ip.append(src)
                        dst_ip.append(dst)
                        stream_no.append(sn)
                        stream_fin.append(0)
                        sheet1.write(i,10,sn)
                        sn = sn + 1
                    elif flag == 1:
                        temp_sn = stream_no[index]
                        src_ip.append(src)
                        dst_ip.append(dst)
                        stream_no.append(temp_sn)
                        stream_fin.append(0)
                        sheet1.write(i,10,temp_sn)
                    elif flag == 2 or flag == 3:
                        del src_ip[index]
                        del dst_ip[index]
                        del stream_no[index]
                        del stream_fin[index]
                        src_ip.append(src)
                        dst_ip.append(dst)
                        stream_no.append(sn)
                        stream_fin.append(0)
                        sheet1.write(i,10,sn)
                        sn = sn + 1
                    index = 0;
            if F & FIN:
                for k in range(length):
                    if src_ip[k] == src and dst_ip[k] == dst:
                        index = k
                        is_del = 1
                        if is_setfin == 1:
                            break
                    elif src_ip[k] == dst and dst_ip[k] == src:
                        stream_fin[k] = 1
                        is_setfin = 1
                        if is_del == 1:
                            break
                del src_ip[index]
                del dst_ip[index]
                del stream_no[index]
                del stream_fin[index]
                index=0
        else:
            for k in range(length):
                if src_ip[k] == src and dst_ip[k] == dst:
                    temp_sn = stream_no[k]
                    sheet1.write(i,10,temp_sn)
                    break
                    
    i = i+1


udp_src_ip = []
udp_dst_ip = []
udp_srcport = []
udp_dstport = []
udp_stream_no = []
i=1
k=0

for packet in packets:
    flag=0
    if "UDP" in packet:
        udp_src = packet['IP'].src
        udp_dst = packet['IP'].dst
        srcport = packet['IP'].sport
        dstport = packet['IP'].dport
        length = len(udp_src_ip)
        if length == 0:
            udp_src_ip.append(udp_src)
            udp_dst_ip.append(udp_dst)
            udp_srcport.append(srcport)
            udp_dstport.append(dstport)
            udp_stream_no.append(sn)
            sheet1.write(i,10,sn)
            sn = sn +1
        else:
            for k in range(length):
                if udp_src_ip[k] == udp_src and udp_dst_ip[k] == udp_dst and udp_srcport[k] == srcport and udp_dstport[k] == dstport:
                    temp_sn = udp_stream_no[k]
                    sheet1.write(i,10,temp_sn)
                    flag = 1;
                    break
                elif udp_src_ip[k] == udp_dst and udp_dst_ip[k] == udp_src and udp_srcport[k] == dstport and udp_dstport[k] == srcport:
                    temp_sn = udp_stream_no[k]
                    sheet1.write(i,10,temp_sn)
                    flag = 1
                    break
            if flag == 0:
                udp_src_ip.append(udp_src)
                udp_dst_ip.append(udp_dst)
                udp_srcport.append(srcport)
                udp_dstport.append(dstport)
                udp_stream_no.append(sn)
                sheet1.write(i,10,sn)
                sn = sn +1
    i = i+1
    


wb.save('new_exd.xls')