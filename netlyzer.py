

import sys
from collections import Counter

import pygeoip
import geocoder
import folium

import pandas as pd
import plotly.express as px

import operator
import numpy as np
from matplotlib import pyplot as plt

import requests
import json

import os

import pygeoip

def apache_output(line):
    split_line = line.split()

    return {'remote_host': split_line[0],
            'Date':split_line[3][1:12],
            'Time':split_line[3][13:],
            'apache_status': split_line[8],
            'data_transfer': split_line[9],
    }

def final_report(logfile):
    for line in logfile:
        line_dict = apache_output(line)
        print(line_dict)


def final_report1(logfile):
    lines=list()
    for line in logfile:
        lines.append(line.split()[0])
    print(lines)
    return lines

def final_report4(logfile):
    lines=list()
    for line in logfile:
        lines.append(line.split()[0])
    #print(lines)
    return lines

def final_report2(logfile):
    lines=list()
    for line in logfile:
        lines.append(line.split()[8])
    print(lines)
    return lines

def final_report3(logfile):
    lines=[]
    for line in logfile:
        lines.append(line.split()[3][13:])
    print(lines)
    return lines


def mapit(ip1):
    g = geocoder.ip(ip1)
    myaddress = g.latlng
    print(myaddress)

    my_map = folium.Map(location=myaddress, zoom_start=12)
    folium.CircleMarker(location=myaddress,radius=50,popup='Yorshire').add_to(my_map)
    my_map.save("my_map.html")




if __name__ == "__main__":
    #blacklisted ips
    blacklist = list()

    #if not len(sys.argv) > 1:
        #print (__doc__)
        #sys.exit(1)
    #infile_name = sys.argv[1]
    infile_name = '/home/ram/Desktop/sample.access.log'
    try:
        infile = open(infile_name, 'r')
    except IOError:
        print ("You must specify a valid file to parse")
        print (__doc__)
        sys.exit(1)

    print("This is a simple analyzer")
    print("1.print the access log")
    print("2.View ips")
    print("3.Map IPS")
    print("4.Check Status codes")
    print("5.Confidence score of an IP")
    print("6.Packet sniffer")
    print("7. Black Listing IPS")
    n=int(input("choice: "))
    if n==1:
        log_report = final_report(infile)
        print (log_report)
    elif n==2:
        ips=final_report1(infile)
        print(len(ips))

        unique_ips = list()
        unique_items = 0
        countries = list()

        for item in ips:
            if item not in unique_ips:
                unique_ips.append(item)

                unique_items += 1
        print("No.of Unique ips are ", unique_items)
        print(unique_ips)

    elif n==3:

        ips = final_report4(infile)
        print(len(ips))

        unique_ips = list()
        unique_items = 0
        countries = list()

        for item in ips:
            if item not in unique_ips:
                unique_ips.append(item)

                unique_items += 1
        #print("No.of Unique ips are ", unique_items)
        #print(unique_ips)

        gip = pygeoip.GeoIP('/home/ram/Documents/GeoLiteCity.dat')
        # res = gip.record_by_addr('152.58.213.230')
        # print(res['country_name'])

        c = 1
        for i in unique_ips:
            res = gip.record_by_addr(i)
            if res == None:
                continue
            else:

                c = c + 1
                countries.append(res['country_name'])

            # print(res['country_name'], res['city'], sep=':')
        print(countries)

        unique_c = list()
        unique_t = 0

        for item in countries:
            if item not in unique_c:
                unique_c.append(item)

                unique_t += 1
        print("No.of Unique countries are ", unique_t)
        print(unique_c)

        freq = {}
        for items in countries:
            freq[items] = operator.countOf(countries, items)

        # for key, value in freq.items():
        #   print("% d : % d" % (key, value))
        print(freq)

        data = pd.DataFrame.from_dict(freq, orient='index', columns=['count'])
        data = data.reset_index().rename(columns={'index': 'country'})

        # Load the country-level geographic data
        url = 'https://raw.githubusercontent.com/python-visualization/folium/master/examples/data'
        geojson = f'{url}/world-countries.json'

        # Plot the choropleth map
        fig = px.choropleth(data, locations='country', color='count',
                            locationmode='country names', geojson=geojson,
                            title='Frequency of the event by country')
        fig.show()

    elif n==4:
        code = final_report2(infile)
        print(len(code))

        x = np.arange(1, len(code)+1)
        y = code
        plt.title("Status code")
        plt.xlabel("Time")
        plt.ylabel("Code")
        plt.plot(x, y)
        plt.show()

    elif n==5:
        con_score = int(input("Minimum Confidence Score : "))
        url = 'https://api.abuseipdb.com/api/v2/check'


        ips=['159.89.166.15']
             #'192.37.115.0', '212.242.33.35', '104.244.40.0']


        headers = {
            'Accept': 'application/json',
            'Key': '2d6d9478608a1a8d5ce23cb75bb396696772b7b19756949b8b3783af3dd6d69c0e4818118a32b730'
        }

        for ip in ips:
            querystring = {
                'ipAddress': ip,
                'maxAgeInDays': '90'
            }
            response = requests.request(method='GET', url=url, headers=headers, params=querystring)
            decodedResponse = json.loads(response.text)
            score= json.dumps(decodedResponse['data']['abuseConfidenceScore'], sort_keys=True, indent=4)
            print("The Confidence Rate of the IP address is: ",score )
            if int(score) > con_score:
                blacklist.append(ip)
            #print(json.dumps(decodedResponse, sort_keys=True, indent=4))
            print(blacklist)
    elif n==6:
        os.system("gnome-terminal -- sudo python3 /home/ram/PycharmProjects/pro/network/packet_sniffer.py")
    elif n==7:
        #os.system("gnome-terminal --full-screen -- /bin/bash -c 'date' bash")
        print("Black Listed IPS :")
        blacklist=['217.168.1.2', '192.37.115.0', '212.242.33.35', '147.137.21.94','255.255.91.136']
        print(blacklist)



