#Import the required Libraries
from tkinter import *
import numpy as np
import matplotlib.pyplot as plt
from matplotlib.backends._backend_tk import NavigationToolbar2Tk
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg
from matplotlib.figure import Figure

#Create an instance of Tkinter frame
win= Tk()

#Set the geometry of tkinter frame
win.geometry("750x550")

def graph():


   # the figure that will contain the plot
   fig = Figure(figsize=(5, 5),dpi=100)

   car_prices = np.random.normal(100000, 5000, 1000)

   plot1 = fig.add_subplot(111)
   plot1.hist(car_prices, 20)

   # creating the Tkinter canvas
   # containing the Matplotlib figure
   canvas = FigureCanvasTkAgg(fig,master=win)
   canvas.draw()

   # placing the canvas on the Tkinter window
   canvas.get_tk_widget().pack()

   # creating the Matplotlib toolbar
   toolbar = NavigationToolbar2Tk(canvas,win)
   toolbar.update()

   # placing the toolbar on the Tkinter window
   canvas.get_tk_widget().pack()

#Create a button to show the plot
Button(win, text= "Show Graph", command= graph).pack(pady=20)
win.mainloop()