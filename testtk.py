#Import the required Libraries
import sys
from tkinter import *
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends._backend_tk import NavigationToolbar2Tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure
from tkinter import filedialog
import tkinter.simpledialog
from ttkSimpleDialog import ttkSimpleDialog

import matplotlib
matplotlib.use('TkAgg')
import numpy as np
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

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

import tkinter as tk

class Page(tk.Frame):
    def __init__(self, *args, **kwargs):
        tk.Frame.__init__(self, *args, **kwargs)
    def show(self):
        self.lift()

class Page1(Page):
   

   def __init__(self, *args, **kwargs):
       def openFile():
          tf = filedialog.askopenfilename(
              initialdir="/home/ram/Desktop/sample.access.log", 
              title="Open Log file", 
              filetypes=(("Log Files", "*.log"),)
              )
          pathh.insert(END, tf)
          tf = open(tf)  # or tf = open(tf, 'r')
          data = tf.read()
          txtarea.insert(END, data)
          tf.close()
       Page.__init__(self, *args, **kwargs)
       label = tk.Label(self, text="Open the access log of the server  where you want to analyze the data")
       label.pack(side="top", fill="both", expand=True)

       txtarea=Text(self, height=50, width=180)
       # txtarea.grid(row=0, column=0, padx=10, pady=10)
       txtarea.pack(pady=20)
       
       pathh = Entry(self)
       pathh.pack(side=LEFT, expand=True, fill=X, padx=20,pady=50)
       
       button =Button(self, text="Open File", command=openFile)
       button.pack(side=RIGHT,expand=True,fill=X, padx=20,pady=50)

     

class Page2(Page):
   def __init__(self, *args, **kwargs):
       def final_report1(logfile):
        lines=list()
        for line in logfile:
            lines.append(line.split()[0])
        #print(lines)
        return lines
       Page.__init__(self, *args, **kwargs)
       label = tk.Label(self, text="The List of all unique IPs in the access log")
       label.pack(side="top", fill="both", expand=True)

       infile_name = '/home/ram/Desktop/sample.access.log'
       try:
           infile = open(infile_name, 'r')
       except IOError:
           print ("You must specify a valid file to parse")
           print (__doc__)
           sys.exit(1)

       
       ips=final_report1(infile)
    #    lbl = tk.Label(self, text = "List Of IPs")
    #    lbl.config(text = "The List of IP: "+str(ips))
    #    lbl.pack()
       lbl = tk.Label(self, text = "Number of unique IPs")
       lbl.config(text = "Number of IPs: "+str(len(ips)))
       lbl.pack()
       #print(len(ips))

       unique_ips = list()
       unique_items = 0
       countries = list()  
       for item in ips:
           if item not in unique_ips:
               unique_ips.append(item)  
               unique_items += 1
       lbl = tk.Label(self, text = "Number of unique IPs")
       lbl.config(text = "Number of Unique IPs: "+str(len(unique_ips)))
       lbl.pack()
       text=Text(self, width=150, height=50)
       text.pack()
       for ip in unique_ips:
          text.insert(END, ip + '\n')
       #print("No.of Unique ips are ", unique_items)
       #print(unique_ips)
     #   button =Button(self, text="Show Ip", command=)
     #   button.pack(side=RIGHT,expand=True,fill=X, padx=20)
class Page3(Page):
   def __init__(self, *args, **kwargs):
       def final_report4(logfile):
          lines=list()
          for line in logfile:
              lines.append(line.split()[0])
          #print(lines)
          return lines
       Page.__init__(self, *args, **kwargs)
       label = tk.Label(self, text="Show the map and the frequency of Users")
       label.pack(side="top", fill="none", expand=False,padx=20,pady=50)
       
       def map():
           
           infile_name = '/home/ram/Desktop/sample.access.log'
           try:
               infile = open(infile_name, 'r')
           except IOError:
               print ("You must specify a valid file to parse")
               print (__doc__)
               sys.exit(1)
           ips = final_report4(infile)
           #print(len(ips))

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
           #print(freq) 

           

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
           
       button =Button(self, text="Open File", command=map)
       button.pack(side=TOP,expand=False, padx=20)

class Page4(Page):
   

   def __init__(self, *args, **kwargs):
       def final_report2(logfile):
          lines=list()
          for line in logfile:
              lines.append(line.split()[8])
          #print(lines)
          return lines
       

       Page.__init__(self, *args, **kwargs)
       label = tk.Label(self, text="Status Code Viewer")
       label.pack(side="top", fill="none", expand=True,padx=20,pady=50)

       infile_name = '/home/ram/Desktop/sample.access.log'
       try:
           infile = open(infile_name, 'r')
       except IOError:
           print ("You must specify a valid file to parse")
           print (__doc__)
           sys.exit(1)
       
       code = final_report2(infile)
       print(len(code))
       def graph():
               import matplotlib.pyplot as plt
               import numpy as np
               x = np.arange(1, len(code)+1)
               y = code
               plt.title("Status code")
               plt.xlabel("Time")
               plt.ylabel("Code")
               plt.plot(x, y)
               plt.show()  
       button =Button(self, text="Show Status Code", command=graph)
       button.pack(side=TOP,expand=False, padx=20)

class Page5(Page):
   

   
   def __init__(self, *args, **kwargs):
       
       Page.__init__(self, *args, **kwargs)
       label = tk.Label(self, text="Check For Malicious IP:('159.89.166.15')")
       label.pack(side="top", fill="x", expand=False,padx=100,pady=50)
       blacklisted = list()
       lbl = tk.Label(self, text = "List Of black Listed IPs")
       lbl.config(text = "The List of BlakListed IP: "+str(blacklisted))
       lbl.pack(side="top", fill="none", expand=False,padx=50,pady=50)
       def check():
          
          con_score = ttkSimpleDialog.askinteger("Input", "Enter the Minimum Confidence score")
          ip1 = ttkSimpleDialog.askstring("Input", "Check this IP ")
          
          
          url = 'https://api.abuseipdb.com/api/v2/check'
          ips=[]
          ips.append(ip1)
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
              
              #label = Label(self, text="The Minimun Confidence Score is : ")
              lbl = tk.Label(self, text = "The Minimum Confidence Score is :")
              lbl.config(text = "Provided Minimum Confidence: "+str(con_score))
              lbl.pack(side="top", fill="both", expand=False)
       
              lbl = tk.Label(self, text = "IP Address: ")
              lbl.config(text = "IP address:"+ips[0])
              lbl.pack(side="top", fill="none", expand=False)

              lbl = tk.Label(self, text = "If the Confidence Rate is above the minimum level Add it to the blacklist/n The Confidence Rate of the IP address is: ")
              lbl.config(text = "If the Confidence Rate is above the minimum level Add it to the blacklist/n The Confidence Rate of the IP address is: "+score)
              lbl.pack(side="top", fill="none", expand=False)
              #label = Label(self, text="The Confidence Rate of the IP address is: ")
              #print("The Confidence Rate of the IP address is: ",score )
              
              
              if int(score) > con_score:
                  blacklisted.append(ip)
              #print(json.dumps(decodedResponse, sort_keys=True, indent=4))
              #print(blacklisted)
              lbl = tk.Label(self, text = "List Of black Listed IPs")
              lbl.config(text = "The List of BlakListed IP: "+str(blacklisted))
              lbl.pack(side="top", fill="none", expand=False)
       button =Button(self, text="Check for malicious IP", command=check)
       button.pack(side=TOP,expand=False, padx=20)


class Page6(Page):
   

   def __init__(self, *args, **kwargs):
       def final_report2(logfile):
          lines=list()
          for line in logfile:
              lines.append(line.split()[8])
          #print(lines)
          return lines
       Page.__init__(self, *args, **kwargs)
       label = tk.Label(self, text="This is page 6")
       label.pack(side="top", fill="both", expand=True)



       
class MainView(tk.Frame):
    def __init__(self, *args, **kwargs):
        tk.Frame.__init__(self, *args, **kwargs)
        p1 = Page1(self)
        p2 = Page2(self)
        p3 = Page3(self)
        p4 = Page4(self)
        p5 = Page5(self)
        p6 = Page6(self)
        buttonframe = tk.Frame(self)
        container = tk.Frame(self)
        buttonframe.pack(side="top", fill="x", expand=False)
        container.pack(side="top", fill="both", expand=True)

        p1.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        p2.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        p3.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        p4.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        p5.place(in_=container, x=0, y=0, relwidth=1, relheight=1)
        p6.place(in_=container, x=0, y=0, relwidth=1, relheight=1)    

        b1 = tk.Button(buttonframe, text="Log Report", command=p1.show)
        b2 = tk.Button(buttonframe, text="IP addresses", command=p2.show)
        b3 = tk.Button(buttonframe, text="Map", command=p3.show)
        b4 = tk.Button(buttonframe, text="Status Code", command=p4.show)
        b5 = tk.Button(buttonframe, text="Malicious IP", command=p5.show)
        b6 = tk.Button(buttonframe, text="", command=p6.show)

        b1.pack(side="left")
        b2.pack(side="left")
        b3.pack(side="left")
        b4.pack(side="left")
        b5.pack(side="left")
        b6.pack(side="left")


        p1.show()

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Network Log Analyzer")
    root.attributes('-fullscreen', True)
    root.configure(background='black')
    main = MainView(root)
    main.pack(side="top", fill="both", expand=True)
    root.wm_geometry("600x700")
    root.mainloop()
