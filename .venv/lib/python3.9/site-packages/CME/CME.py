#!/usr/bin/env python


"""This file is part of the Colour-Magnitude Explorer.

    The Colour-Magnitude Explorer is free software: you can
    redistribute it and/or modify it under the terms of the GNU
    General Public License as published by the Free Software
    Foundation, either version 3 of the License, or (at your option)
    any later version.

    The Colour-Magnitude Explorer is distributed in the hope that it
    will be useful, but WITHOUT ANY WARRANTY; without even the implied
    warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
    See the GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with The Colour-Magnitude Explorer.  If not, see <http://www.gnu.org/licenses/>.
 
   Copyright 2015, Jennifer Karr
   All rights reserved.   
   Contact: Jennifer Karr (jkarr@asiaa.sinica.edu.tw)



   -----

   This is the main program for the Colour Magnitude Explorer

   Version 0.1 (beta) Last Updated April 15 2015

"""

import matplotlib
matplotlib.use('TkAgg')
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg, NavigationToolbar2TkAgg
from matplotlib.figure import Figure

from pylab import * 
from Tkinter import *
import tkMessageBox
import tkFileDialog 
from tkFont import Font 
import numpy
import os
from matplotlib import rcParams
from scipy.interpolate import interp1d
import pickle
import pkg_resources
import string

#========================================================================

class main_win(Frame):
    """

    MAIN WINDOW

    """

    def __init__(self,master=None): 
        Frame.__init__(self,master) 
      
        self.master.title('Colour-Magnitude Explorer')

        self.markupnum=0

        ##FOR OUTLAY OF PLOTS
        rcParams.update({'figure.autolayout': True})

        ####################################################################
        ##INITIALIZE GLOBAL VARIABLES 

        self.alldata={}          ##MASTER DICTIONARY 
        self.allover={}          ##OVER PLOT INFORMATION

        ##DICTIONARY TO HOLD THE DATA. THE FORM IS A NESTED DICTIONARY
        ##
        ##newfile[filename] IS THE DICTIONARY FOR A PARTICULAR FILE. 
        ##
        ##INSIDE THAT DICTIONARY THERE ARE THE TAGS
        ##
        ## flux = ORDERED LIST OF FLUXES
        ## ferr = ORDERED LIST OF ERRORS TO GO WITH THE FLUXES
        ## mag = ORDERED LIST OF MAGNITUDES
        ## merr = ORDERED LIST OF MAGNITUDE ERRORS TO GO WITH THE FLUXES
        ##
        ## EACH OF THE ABOVE TAGS IS ASSOCIATED WIHT A NUMPY ARRAY OF DIMENSIONS (NCOL,NWAVE)
        ##
        ## label = ORDERED LIST OF SOURCE IDS (CHAR STRING), DIMENSION (NCOL)
        ## ra = ORDERED LIST OF RIGHT ASCENSION (FLOAT), DIMENSION (NCOL)
        ## dec = ORDERED LIST OF DECLINATION (FLOAT), DIMENSION (NCOL)


        self.filelist=[]         ##LIST OF FILE NAMES THAT HAVE BEEN READ IN 
        self.wavelist=[]         ##LIST OF UNIQUE AVAILABE WAVELENGTHS TAGS, SORTED BY WAVELENGTH

        self.overfilelist=[]     ##LIST OF FILE NAMES THAT HAVE BEAN READ IN FOR OVERPLOTS 

        self.accepted_units=['jy','mjy','ujy','erg/cm2/hz','w/m2/hz','mag']  #??check
        self.sdss_waves=['u','g','r','i','z']
        self.sdss_abfix={'u':-0.036,'g':0.012,'r':0.010,'i':0.028,'z':0.040}
        self.sdss_b={'u':1.4e-10,'g':0.9e-10,'r':1.2e-10,'i':1.8e-10,'z':7.4e-10}

        ##DICTIONARY TO HOLD THE INFORMATION FOR LOADED FILES - MOSTLY LISTS

        self.fileinfo={"filewind":[],        #FILE WINDOW MENU
                       "filelabel":[],       #NAME OF FILE
                       "files":[],           #FILE LABEL VARIABLE (DIFFERENT FROM NAME OF FILE)
                       "colmenu":[],         #COLOUR MENU
                       "symmenu":[],         #SYMBOL MENU
                       "syms":[],            #SYMBOL VARIABLE
                       "cols":[],            #COLOUR VARIABLE
                       "active":[],          #ACTIVE FLAG
                       "activemenu":[],      #MENU FOR ACTIVE FLAG
                       "scale":[],           #VARIABLE FOR SCALING FACTOR
                       "scalemenu":[],       #MENU FOR SCALING FACTOR
                       "nfiles":0}           #NUMBER OF LOADED FILES

        ##DICTIONARY TO HOLD INFORMATION FOR OVERPLOTS FILES - MOSTLY LISTS

        self.overinfo={"filewind":[],        #FILE WINDOW MENU
                       "filelabel":[],       #NAME OF FILE
                       "files":[],           #FILE LABEL VARIABLE (DIFFERENT FROM NAME OF FILE)
                       "colmenu":[],         #COLOUR MENU
                       "linemenu":[],        #SYMBOL MENU
                       "lines":[],           #SYMBOL VARIABLE
                       "cols":[],            #COLOUR VARIABLE
                       "active":[],          #ACTIVE FLAG
                       "activemenu":[],      #MENU FOR ACTIVE FLAG
                       "scale":[],           #VARIABLE FOR SCALING FACTOR
                       "scalemenu":[],       #MENU FOR SCALING FACTOR
                       "nfiles":0}           #NUMBER OF LOADED FILES

        ##SYMBOL SET FOR PLOTS - UTF-8 FORMAT
        
        self.symset={u'\u25FC':'d',
                     u'\u25FC':'s',
                     u'\u25C6':'D',
                     u'\u25CF':'o',
                     u'\u2605':'*',
                     u'\u29EB':'d',
                     'x':'x',
                     '+':'+'}

        self.symsize={u'\u25FC':1,
                     u'\u25FC':1,
                     u'\u25C6':1,
                     u'\u25CF':1.3,
                     u'\u2605':1.8,
                     u'\u29EB':1,
                     'x':1.2,
                     '+':1.3}

        self.symthick={u'\u25FC':1,
                     u'\u25FC':1,
                     u'\u25C6':1,
                     u'\u25CF':1,
                     u'\u2605':1,
                     u'\u29EB':1,
                     'x':2,
                       '+':2}


        #DICTIONARY TO HOLD THE VARIABLES FOR THE DIFFERENT AXES 

        self.axis={'x1':StringVar(),
                   'x2':StringVar(),
                   'y1':StringVar(),
                   'y2':StringVar()}

        #VARIOUS FLAGS AND USER PROVIDED INFORMATION

        self.showext=IntVar()   #SHOW EXTINCTION VECTORS
        self.filt=IntVar()      #SHOW FILTER VALUES
        self.uncert=IntVar()    #SHOW UNCERTAINTIES
 
        self.filetype=StringVar()  #CHOICE OF TYPE OF FILE FOR INPUT
        self.whichplot=IntVar()    #CHOICE OF WHETHER TO PLOT CC/CM OR POSITION
        #self.nufnu=IntVar()        #FLAG FOR NU F NU VS LAMBDA F LAMBDA SED PLOT

        self.loaded=0           #FLAG TO TRACK WHETHER AT LEAST ONE FILE IS LOADED

        self.usertitle=StringVar()  ##USER PROVIDED TITLE

        self.m_currentRow = 2   #KEEP TRACK OF CURRENT ROW FOR FILE LIST
        self.n_currentRow = 2   #KEEP TRACK OF CURRENT ROW FOR OVERPLOT LIST

        ##VARIABLES TO HOLD LIMITS FOR CC BOX

        self.xfmin=StringVar()
        self.xfmax=StringVar()
        self.yfmin=StringVar()
        self.yfmax=StringVar()

        #USER PROVIDED VISUAL EXTINCTION
        self.av=StringVar()

        ##SOME OTHER IMPORTANT VARIABLE DEFINITIONS

        ##self.limits        #CURRENTS LIMITS OF THE MAIN PLOT
        ##self.olimits       #ORIGINAL LIMITS OF THE MAIN PLOT - KEPT FOR PURPOSES OF ZOOMING/UNZOOMING
        ##self.extinct_law   #AN INTERPOLATION OF INTERSTELLAR EXTINCTION LAW FOR USE IN 
                             #PLOTTING EXTINCTION VECTOR
        
        ##self.arrow         #A VARIABLE TO KEEP TRACK OF THE ARROW PLOT ELEMENT (SO WE CAN ERASE IT)
        ##self.markup        #A VARIABLE TO KEEP TRACK OF THE MARKED POINT FOR THE SED PLOT
                             #WE NEED TO KEEP TRACK OF IT SO WE CAN DELETE AND RESET IT


        #========================================================================

        #READ IN THE CALIBRATION FILES TO INITIALIZE

        self.get_calib()

        #CALCULATE THE EXTINCTION FUNCTION
        self.get_extinct()

        #========================================================================
    
        #WINDOW LAYOUT
        
        #WINDOW IS DIVIDED INTO FOUR SECTIONS, LEFTTOP, RIGHTTOP, LOWERRIGHT, LOWERLEFT
        #UPPER RIGHT = MAIN CONTROL FUNCTIONS
        #UPPER LEFT  = SCROLLABLE WINDOW WITH FILES AND FILE OPTIONS
        #LOWER RIGHT = MAIN PLOT WINDOW
        #LOWER LEFT  = SED PLOT AND PLOT OPTIONS
        
        #===========LEFT

        self.leftframe=Frame(self)
        ##LEFTTOP - MAIN CONTROL FUNCTIONS
        lefttop=Frame(self.leftframe)
        
        #BASIC CONTROLS FOR THE PROGRAM - QUIT, HELP
        frame1=Frame(lefttop) 
        frame1_mb1=Button(frame1,text='Quit',command=self.quit)
        frame1_mb1.config(background="red")
        frame1_mb1.grid(row=0,column=0) 
        frame1_mb2=Button(frame1,text='Help',command=self.placeholder).grid(row=0,column=1)

        #MAKE NEW PLOT
        frame1_mb3=Button(frame1,text='Update Plot',command=self.make_plot).grid(row=0,column=2)

        frame1.grid(row=0,column=0,sticky=NW) 


        #LOAD A CATALGOUE
        
        frame2=Frame(lefttop)
        frame2_mb1=Button(frame2,text='Load File',command=self.choose_input).grid(row=0,column=1)

        ##SELECT THE FORM OF THE INPUT

        frame2_mb2=OptionMenu(frame2,self.filetype,"Text","IRSA","SDSS")
        frame2_mb2.configure(width=8)
        frame2_mb2.grid(row=0,column=2)

        #LOAD AN OVERPLOT FILE
        frame2_mb3=Button(frame2,text='Load Overplot',command=self.read_overplot).grid(row=0,column=3)

        #CHOOSE BETWEEN CC/CM PLOT AND POSITION PLOT
        frame2_mb4=Radiobutton(frame2,text='Colour Plot',variable=self.whichplot,value=1).grid(row=0,column=4)
        frame2_mb5=Radiobutton(frame2,text='Position Plot',variable=self.whichplot,value=2).grid(row=0,column=5)

        frame2.grid(row=1,column=0,sticky=NW)

        self.filetype.set('IRSA')  
        self.whichplot.set(1)

        #VARIOUS OPTIONS - EXTINCTION VECTOR, UNCERTAINTIES, FILTER VALUES
        self.options=Frame(lefttop)
        options_mb1=Checkbutton(self.options,variable=self.showext,text='Show Extinction: Av=').grid(row=0,column=0)
        options_entry1=Entry(self.options,textvariable=self.av,width=5).grid(row=0,column=1)
        options_mb2=Checkbutton(self.options,variable=self.uncert,text="Plot Uncertainties").grid(row=0,column=2)
        self.options.grid(row=2,column=0)

        self.av.set('5')

        ##USER PROVIDED PLOT TITLE
        self.gettitle=Frame(lefttop)
        self.gettitle_label=Label(self.gettitle,text="Plot Title: ").grid(row=0,column=0)
        self.gettitle_title=Entry(self.gettitle,textvariable=self.usertitle).grid(row=0,column=1)
        self.gettitle.grid(row=3,column=0,sticky=W)
        
        #CHOICES FOR THE PLOTS. THE OPTIONMENU IS UPDATED EVERY TIME A NEW FILE IS LOADED, WITH THE NEW
        #LIST OF WAVELENGTHS. 
        #FOUR MENUS - ONE FOR EACH FILTER (TWO FILTERS NEEDED FOR EACH COLOUR). 
        #'NONE' IS APPENDED TO THE SECOND Y AXIS, FOR CM DIAGRAMS

        self.axischoice1=Frame(lefttop)
        self.axischoice1_label=Label(self.axischoice1,text="X Axis").grid(row=0,column=0)
        self.axischoice1_x1=OptionMenu(self.axischoice1,self.axis['x1'],'')
        self.axischoice1_x1.config(width=12)
        self.axischoice1_x1.grid(row=0,column=1)

        self.axischoice1_label=Label(self.axischoice1,text="-").grid(row=0,column=2)
        self.axischoice1_x2=OptionMenu(self.axischoice1,self.axis['x2'],'')
        self.axischoice1_x2.grid(row=0,column=3)
        self.axischoice1_x2.config(width=12)
        self.axischoice1.grid(row=4,column=0)
        
        self.axischoice2=Frame(lefttop)
        self.axischoice2_label=Label(self.axischoice2,text="Y Axis").grid(row=0,column=0)
        self.axischoice2_y1=OptionMenu(self.axischoice2,self.axis['y1'],'')
        self.axischoice2_y1.config(width=12)
        self.axischoice2_y1.grid(row=0,column=1)

        self.axischoice2_label=Label(self.axischoice2,text="-").grid(row=0,column=2)
        self.axischoice2_y2=OptionMenu(self.axischoice2,self.axis['y2'],'')
        self.axischoice2_y2.grid(row=0,column=3)
        self.axischoice2_y2.config(width=12)
        self.axischoice2.grid(row=5,column=0)

        lefttop.grid(row=0,column=0,sticky=NW)


        #LEFTMIDDLE - MAIN PLOT WINDOW

        self.leftmiddle=Frame(self.leftframe)

        ##CREATE THE FIRST FIGURE AND ADD AN AXIS

        self.fig1 = Figure(figsize=(6,6))
        self.ax1 = self.fig1.add_subplot(111)

        ##NOW CREATE A TKAGG CANVAS AND ATTACH THE PLOT TO IT. 

        fm1=Frame(self.leftmiddle,relief=RAISED, bd=1)
        self.canvas1 = FigureCanvasTkAgg(self.fig1, master=fm1)
        self.canvas1.get_tk_widget().grid(row=0,column=0)
        fm1.grid(row=0,column=0)
        self.leftmiddle.grid(row=1,column=0)
    
        #ADD THE BUTTONS FOR ZOOM FUNCTIONS

        self.leftbottom=Frame(self.leftframe)
        
        self.zoom=Frame(self.leftbottom)
        zoom_mb1=Button(self.zoom,text="Zoom",command=self.zoomin).grid(row=0,column=0)
        zoom_mb2=Button(self.zoom,text="UnZoom",command=self.zoomout).grid(row=0,column=1)
        zoom_mb3=Button(self.zoom,text="Reset",command=self.replot).grid(row=0,column=2)
        self.zoom.grid(row=0,column=0,sticky=SW)
        
        self.leftbottom.grid(row=2,column=0)

        self.leftframe.grid(row=0,column=0)

        #===========RIGHT

        self.rightframe=Frame(self)


        #RIGHTTOP - FILE INFORMATION. CONSISTS OF A CANVAS WITH A SCROLLBAR AND A FRAME
        #           ATTACHED TO IT. THE CODE IS A BIT IMPENETRABLE LOOKING, BUT IT DOES
        #           WORK, SO I'M NOT FIDDLING WITH IT MORE.  

        self.righttop=Frame(self.rightframe,bd=2,relief=RAISED)
        
        #CREATE A CANVAS
        self.filecanvas=Canvas(self.righttop)

        #CREATE A FRAME WITHIN THE CANVAS

        self.fileframe=Frame(self.filecanvas)

        #CREATE A SCROLLBAR, ATTACHED TO THE SURROUNDING FRRAME, ATTACHED TO A COMMAND

        self.vsb=Scrollbar(self.righttop,orient=VERTICAL,command=self.filecanvas.yview)

        #CONFIGURE THE CANVAS TO ATTACH THE SCROLLBAR, AND FILL TO FIT THE WHOLE WINDOW

        self.filecanvas.configure(yscrollcommand=self.vsb.set)
        self.vsb.pack(side="right",fill="y")

        #NOW CREATE A WINDOW IN THE CANVAS, ATTACHED TO THE FRAME WITHIN THE CANVAS. BIND THE
        #FRAME USING A CONFIGURE FUNCTION, AND PACK (NOT GRID)

        self.filecanvas.create_window((0,0),window=self.fileframe,anchor="nw",tags="self.filelist")
        self.fileframe.bind("<Configure>",self.OnFrameConfigure)
        self.filecanvas.pack(side="left",fill="both")
 
        ##NOW SOME CONTENT FOR OUR OVERLY COMPLICATED WINDOW WITH SCROLLBAR

        ##LABELS FOR THE COLUMNS

        self.labs=Frame(self.fileframe)
        labs_mb1=Label(self.labs,text="Catalogue File",width=30).grid(row=0,column=0,sticky=N)
        labs_mb2=Label(self.labs,text="Colour",width=12).grid(row=0,column=2,sticky=N)
        labs_mb3=Label(self.labs,text="Sym",width=4).grid(row=0,column=3,sticky=N)
        labs_mb4=Label(self.labs,text="d",width=5).grid(row=0,column=4,sticky=N)
        self.labs.grid(row=0,column=0)

        self.righttop.grid(row=0,column=1,sticky=NW)
        self.righttop.configure(width=200)
   
        #RIGHTMIDDLE - OVERPLOT FILE INFORMATION. CONSISTS OF A CANVAS
        #              WITH A SCROLLBAR AND A FRAME ATTACHED TO IT
        #THIS IS EXACTLY THE SAME AS THE CODE IN RIGHTTOP, BUT FOR OVERPLOT FILES

        #FRAME, CANVAS AND SCROLLBAR

        self.rightmiddle=Frame(self.rightframe,bd=1,relief=RAISED)
        
        self.filecanvas1=Canvas(self.rightmiddle)
        self.fileframe1=Frame(self.filecanvas1)
        self.vsb1=Scrollbar(self.rightmiddle,orient=VERTICAL,command=self.filecanvas1.yview)
        self.filecanvas1.configure(yscrollcommand=self.vsb1.set)
        self.vsb1.pack(side="right",fill="y")
        self.filecanvas1.create_window((0,0),window=self.fileframe1,anchor="nw",tags="self.filelist")
        self.fileframe1.bind("<Configure>",self.OnFrameConfigure2)
        self.filecanvas1.pack(side="left",fill="both")
 
        ##NOW THE LABELS
        self.labs1=Frame(self.fileframe1)
        labs_mb1=Label(self.labs1,text="Overplot File",width=30).grid(row=0,column=0,sticky=N)
        labs_mb2=Label(self.labs1,text="Colour",width=12).grid(row=0,column=2,sticky=N)
        labs_mb3=Label(self.labs1,text="Line",width=4).grid(row=0,column=3,sticky=N)
        labs_mb4=Label(self.labs1,text="d",width=5).grid(row=0,column=4,sticky=N)
        self.labs1.grid(row=0,column=0)

        self.rightmiddle.grid(row=1,column=1,sticky=NW)
        self.rightmiddle.configure(width=200)

        #RIGHTBOTTOM - CONTAINS SED PLOT AND PLOT OPTIONS
        
        self.rightbottom=Frame(self.rightframe)
    
        ##CONTROL BUTTONS - SAVING THE PLOTS TO GRAPHICS FILES, AND SWITCHING FROM WAVELENGTH TO 
        ##FREQUENCY UNITS

        self.savebutton=Frame(self.rightbottom)
        savebutton_mb1=Button(self.savebutton,text='Save Main Plot',command=self.save_main).grid(row=0,column=0,sticky=N)
        savebutton_mb2=Button(self.savebutton,text='Save SED Plot',command=self.save_sed).grid(row=0,column=1,sticky=N)
        #options_mb1=Checkbutton(self.savebutton,variable=self.nufnu,text=u'\u03BD'+"F"+u'\u03BD').grid(row=0,column=2)
        self.savebutton.grid(row=0,column=0,sticky=N)

        ##THE SED PLOTS
        
        ##CREATE THE FIGURE AND ADD AN AXIS
        
        self.fig2 = Figure(figsize=(6,3))
        self.ax2 = self.fig2.add_subplot(111)
    
        ##CREATE A SECOND CANVAS AND ATTACH THE FIGURE TO IT  
        
        fm2=Frame(self.rightbottom,relief=RAISED, bd=1)
        self.canvas2 = FigureCanvasTkAgg(self.fig2, master=fm2)
        self.canvas2.get_tk_widget().grid(row=0,column=0)
        self.canvas2.show()
        fm2.grid(row=1,column=0,sticky=N)
        
        #USER PROVIDED LIMITS TO DRAW ON PLOT
        
        self.filt1=Frame(self.rightbottom)
        filt1_mb1=Label(self.filt1,text="X Axis Box",width=10).grid(row=3,column=0,sticky=W)
        filt1_mb2=Entry(self.filt1,master,textvariable=self.xfmin).grid(row=3,column=1)
        filt1_mb3=Entry(self.filt1,master,textvariable=self.xfmax).grid(row=3,column=2)
        self.filt1.grid(row=2,column=0,sticky=N)

        self.filt2=Frame(self.rightbottom)
        filt2_mb1=Label(self.filt2,text="Y Axis Box",width=10).grid(row=3,column=0,sticky=W)
        filt2_mb2=Entry(self.filt2,master,textvariable=self.yfmin).grid(row=3,column=1)
        filt2_mb3=Entry(self.filt2,master,textvariable=self.yfmax).grid(row=3,column=2)
        self.filt2.grid(row=3,column=0,sticky=N)

        self.rightbottom.grid(row=3,column=1)

        self.rightframe.grid(row=0,column=1)

        #FINISH THE MAIN WINDOW SET-UP

    #========================================================================


        ##NOW SOME ROUTINES TO CONFIGURE THE MOUSE BINDINGS FOR INTERACTING
        ##WITH THE CC PLOT. 

        ##ALSO INCLUDES KEY BINDINGS FOR PEOPLE WITHOUT THREE BUTTON MICE
        ##NOTE THAT THREE BUTTON MOUSE EMULATION W/ TRACKPAD DOESN'T WORK

        ##LEFT MOUSE BUTTON   - CLICK, DRAG AND RELEASE FOR REGION-ZOOM
        ##MIDDLE MOUSE BUTTON - CLICK TO RE-CENTER THE IMAGE (PAN) [OR C FOR CENTRE]
        ##RIGHT MOUSE BUTTON  - CLICK TO SELECT A POINT [OR M FOR MARK]
        #
        #CLICK IN REGION WITH ANY BUTTON TO SET FOCUS
        #
        #WHILE FOCUSED - "C" OR "c" TO PAN, "m" or "M" TO MARK

    #========================================================================

        def on_key_main(event):
                

            """

            #SET THE KEY BINDINGS

            """

            #READ THE CURRENT MOUSE POSITION WHEN THE KEY IS PRESSED
            self.xo=event.xdata
            self.yo=event.ydata

            #RECENTER WITH THE SAME SCALE
            if((event.key == "c") | (event.key == "C")):
                
                #CALCULATE AND SET NEW LIMITS
                self.pan(self.xo,self.yo)
            
                #PUT NEW LIMITS IN VARIABLE
                self.limits=self.ax1.axis()
            
                #REDRAW EXTINCTION ARROW
                self.get_arrow()
            
                #REDRAW CANVAS
                self.canvas1.draw()

            #MARK A POINT AND PLOT AN SED

            if((event.key == "M") | (event.key == "m")):
        
                #CALL ROUTINE TO MARK AND DRAW SED
                self.get_sed()

        #========================================================================
                
        def on_click_main(event):
    
            """

            ROTINE TO SET THE MOUSE BINDINGS FOR CLICKING THE MOUSE

            """

            ##READ THE X AND Y POSITIONS OF THE START POINT, IN PIXEL AND DATA UNITS
            self.xo=event.xdata
            self.yo=event.ydata
            self.xo_r=event.x
            self.yo_r=event.y

            ##MIDDLE BUTTON CLICK - PAN. KEEP CURRENT IMAGE SCALE BUT CHANGE CENTRE
            if(event.button==2):

                #CALCULATE AND SET LIMITS

                self.pan(self.xo,self.yo)

                #PUT LIMITS INTO VARIABLE

                #RECOMPUTE EXTINCTION ARROW
                self.get_arrow()

                #REDRAW CANVAS
                self.canvas1.draw()
                
                ##RIGHT BUTTON - SELECT A POINT 
            elif(event.button==3):

                #CALL ROUTINE TO SELECT AND DRAW SED
                self.get_sed()
        
                #LEFT BUTTON - DO NOTHING FOR NOW
            elif(event.button==1):
                pass

            ##SET FOCUS TO CANVAS FOR KEY BINDINGS FOR ANY CLICK
            self.canvas1._tkcanvas.focus_set()

        #========================================================================

        def off_click_main(event):
        
            """

            SET THE MOUSE BINDINGS FOR RELEASING THE MOUSE BUTTON ON A DRAG AND DROP

            """

            #READ THE X AND Y POSITIONS OF THE MOUSE WHEN RELEASING THE BUTTON, PIXEL AND DATA
            self.xn=event.xdata
            self.yn=event.ydata
            self.xn_r=event.x
            self.yn_r=event.y

            ##IF IT'S THE LEFT BUTTON, GET THE NEW BOUNDARIES AND REPLOT

            if(event.button==1):

                ##IGNORE A ZOOM OF LESS THAN 10 PIXELS, IN THE EVENT OF A LEFT BUTTON CLICK WITH NO DRAG

                zoomd=sqrt((self.xo_r-self.xn_r)**2+(self.yo_r-self.yn_r)**2)
                if(zoomd > 10):

                    ##MIN/MAX - SWAP FOR
                    #SET NEW LIMITS
                    self.ax1.set_xlim([self.xo,self.xn])
                    self.ax1.set_ylim([self.yo,self.yn])
                
                    #PUT LIMITS INTO VARIABLE
                    self.limits=self.ax1.axis()
                    self.check_limits()
                
                    #RECOMPUTE EXTINCTION ARROW
                    self.get_arrow()
                
                    #AND REDRAW
                    self.canvas1.draw()
                
        #LINK ONCLICK/OFFCLICK TO THE APPROPRIATE CANVAS - CAN ADD DIFFERENT METHODS FOR OTHER CANVASES

        cid = self.fig1.canvas.mpl_connect('button_press_event', on_click_main)
        cid = self.fig1.canvas.mpl_connect('button_release_event', off_click_main)
        cid = self.fig1.canvas.mpl_connect('key_press_event', on_key_main)


    #========================================================================
    #THESE ARE CONFIGURATION ROUTINES FOR THE SCROLLBAR/CANVAS SETUP, SETTING
    #THE WIDTH APPROPRIATELY.

    def OnFrameConfigure(self,event):

        """

        CONFIGURE THE FILE LIST CANVAS WITH THE SCROLLBAR. SET THE SCROLL REGION, AND EXPAND
        THE WIDTH TO FIT THE CONTENTS.

        """
        self.filecanvas.configure(scrollregion=self.filecanvas.bbox("all"),)
        self.filecanvas.config(width=480)

    #========================================================================

    def OnFrameConfigure2(self,event):

        """

        CONFIGURE THE FILE LIST CANVAS WITH THE SCROLLBAR. SET THE SCROLL REGION, AND EXPAND
        THE WIDTH TO FIT THE CONTENTS.

        """
        self.filecanvas1.configure(scrollregion=self.filecanvas1.bbox("all"),)
        self.filecanvas1.config(width=480,height=150)

    #========================================================================


    #END OF SETTING UP BINDINGS. 

    #========================================================================
    #INITIALIZATION ROUTINES

    def get_extinct(self):

        """
        
        INITIALIZE THE INTERSTELLAR EXTINCTION LAW FOR THE EXTINCITON VECTOR

        INTERSTELLAR EXTINCTION LAW TAKEN FROM (MATHIS, ARA&A 1990. 28: 37-70) 
        http://ned.ipac.caltech.edu/level5/Mathis/Mathis_contents.html
        FOR R_V=3.1
        
        EMPIRCAL DATA BELOW LAMBDA=250, ABOVE, SCALE  A(250) BY (250/LAM)^2

        """

        #WAVELENGTH ARRAY


        self.lam=array([0.002,0.004,0.023,0.041,0.073,0.091,0.12,0.13,0.15,0.18,0.2,0.218,0.24, 0.26,0.28,0.33,0.365,0.44,0.55,0.7,0.9,1.25,1.65,2.2,3.4,5.,7.,9.,9.7,10.,12.,15.,18.,20.,25.,35.,60.,100.,250.,350.,500.,750.,1000.,1300.,1600.,2000.,2500.,3000.,5000.,10000.])

        #EXTINCTION. PAPER GIVES A(LAM)/A(J), NEED TO DIVIDE BY 3.55, TO GET EXTINCITON IN TERMS OF 
        #A(V), WHICH IS MORE STANDARD

        self.ext=array([1.35,3.39,7.31,9.15,19.1,17.2,12.71,11.09,9.44,8.93,10.08,11.29,9.03,7.63,6.9,5.87,5.53,4.7,3.55,2.66,1.7,1,0.624,0.382,0.182,0.095,0.070,0.157,0.208,0.192,0.098,0.053,0.083,0.075,0.048,0.013,0.0071,0.0041,0.0015,7.653e-04,3.750e-04,1.667e-04,9.375e-05,5.547e-05,3.662e-05,2.344e-05,1.500e-05,1.042e-05,3.750e-06,9.375e-07])/3.55

        ##GET AN INTERPOLATED FUNCTION FOR LATER USE. 
        self.extinct_law=interp1d(self.lam,self.ext)

    #============================================================================

    def get_calib(self):

        """
        
        ROUTINE TO READ IN THE FLUX CALIBRATION FILE. 
        
        INPUT FORMAT

        TEXT FILE, COLUMNS SEPARATED BY TABS (NOT SPACES), LINES BEGINNING WITH # ARE IGNORED
        EACH LINE HAS 5 COLUMNS
        - UNIQUE TAG FOR THE WAVELENGTH - SHOULD BE ASCII STRING
        - LABEL FOR MAGNITUDES - LATEX COMPLIANT STRING
        - LABEL FOR FLUXES - LATEX COMPLIANT STRING
        - CENTRE WAVELENGTH (IN MICRONS)
        - CALIBRATION FLUX (IN JY)
        
        A FLUX CALIBRATION OF 0 INDICATES THAT THERE IS NO FLUX STANDARD FOR THIS FILTER, AND 
        INSTEAD OF MAGNITUDES, LOG10(F) WILL BE USED.
    
        THE USER CAN MANUALLY ADD ENTRIES TO THE FILE
        
        """

        #DICTIONARY TO HOLD THE INFORMATION
        self.waveval={}
        self.waveband={}
        self.irsaval={}

        resource_package = __name__  ## Could be any module/package name.
        resource_path = os.path.join('calibration_files', 'fluxcalib.txt')
        filecontents = pkg_resources.resource_string(resource_package, resource_path)

        #LOAD THE FILE, READ THROUGH THE LINES, AND ASSIGN
        f=string.split(filecontents,'\n')
        #f=open(inputfile)
        for line in f:
            if (line.strip() != ''):
                if (line[0] != "#"):
                    newval=line.split("\t")

                    self.waveval[newval[0]]=[newval[1],newval[1],float(newval[3])]

        resource_path = os.path.join('calibration_files', 'irsa_calib.txt')
        filecontents = pkg_resources.resource_string(resource_package, resource_path)

        #f=open("irsa_calib.txt")
        f=string.split(filecontents,'\n')

        for line in f:
            if (line.strip() != ''):
                if (line[0] != "#"):

                    newval=line.split()
                    self.irsaval[newval[0]]=[newval[1],float(newval[2]),float(newval[3])]

        resource_path = os.path.join('calibration_files', 'bandlist.txt')
        filecontents = pkg_resources.resource_string(resource_package, resource_path)

        #f=open("bandlist.txt")
        f=string.split(filecontents,'\n')

        for line in f:
           if (line.strip() != ''):
                if (line[0] != "#"):
                    
                    newval=line.split("\t")
                    print line
                    self.waveband[newval[0]]=[newval[1],float(newval[2])]

 
    #========================================================================
    #NOW SOME ROUTINES TO MANIPULATE THE DISPLAYED PLOTS

    def pan(self,x,y):

        """
        
        PAN TO A SPECIFIED CENTRE, KEEPING THE SAME SCALE
        
        """

        xrange=(self.limits[1]-self.limits[0])/2.
        yrange=(self.limits[3]-self.limits[2])/2.
        self.ax1.set_xlim([x-xrange,x+xrange])
        self.ax1.set_ylim([y-yrange,y+yrange])
        self.limits=self.ax1.axis()

    #========================================================================
    def zoomin(self):

        """
        ZOOM FUNCTION - ZOOMS IN ON THE CURRENT CENTRE BY A FACTOR OF TWO
        """
 
        ##GET 1/2 THE VALUE OF THE CURRENT DISTANCE BETWEEN THE CENTRE AND EDGE

        xrange=(self.limits[1]-self.limits[0])/4.
        yrange=(self.limits[3]-self.limits[2])/4.
            
        ##GET THE CURRENT CENTRE
        xcen=(self.limits[1]+self.limits[0])/2.
        ycen=(self.limits[3]+self.limits[2])/2.
            
        ##SET THE NEW LIMITS
        self.ax1.set_xlim([xcen-xrange,xcen+xrange])
        self.ax1.set_ylim([ycen-yrange,ycen+yrange])

        #GET NEW LIMITS
        self.limits=self.ax1.axis()

        #PLOT EXTINCTION VECTOR
        self.get_arrow()

        ##AND REDRAW
        self.canvas1.draw()


    #========================================================================
    def zoomout(self):
            
        """
        ZOOM FUNCTION - ZOOMS IN ON THE CURRENT CENTRE BY A FACTOR OF TWO
        """
 
        ##GET 2X THE VALUE OF THE CURRENT DISTANCE BETWEEN THE CENTRE AND EDGE
            
        xrange=(self.limits[1]-self.limits[0])
        yrange=(self.limits[3]-self.limits[2])
            
        ##GET THE CURRENT CENTRE
        xcen=(self.limits[1]+self.limits[0])/2.
        ycen=(self.limits[3]+self.limits[2])/2.

        ##SET THE NEW LIMITS
        self.ax1.set_xlim([xcen-xrange,xcen+xrange])
        self.ax1.set_ylim([ycen-yrange,ycen+yrange])

        ##AND READ THE VALUES
        self.limits=self.ax1.axis()

        #OVER PLOT THE EXTINCTION VECTOR, AND RE-DRAW
        self.get_arrow()
        self.canvas1.draw()


    #========================================================================

    def replot(self):
   
        """

        THIS ROUTINE RESETS THE PLOT LIMITS TO THE ORIGINAL VALUES 
        BUT DOESN'T CHANGE ANYTHING ELSE (UNLIKE THE RE-PLOT ROUTINE)

        ???CHECK IF THIS IS REDUNDANT WITH THE NEW CODE

        UNLIKE "NEW PLOT" THIS KEEPS THE OVERPLOTTED POINTS, BOX, ETC.

        """

        #SET THE PLOT LIMITS TO THE ORIGINAL AUTOMATIC LIMITS
        self.ax1.set_xlim([self.olimits[0],self.olimits[1]])
        self.ax1.set_ylim([self.olimits[2],self.olimits[3]])

        #READ THE NEW LIMITS
        self.limits=self.ax1.axis()
       
        #DRAW EXTINCTION VECTOR
        self.get_arrow()

        #DRAW BOX
        self.make_limits()

        #REPLOT
        self.canvas1.draw()


    #========================================================================
    def check_limits(self):
        
        """

        CHECK IF THE LIMITS OF THE PLOT ARE THE RIGHT WAY ROUND, FOR CC AND CM DIAGRAMS.
        THIS IS NEEDED FOR SELECTING A ZOOM REGION (THE USER CAN DRAG BOTH WAYS)
        AND TO PLOT THE MAGNITUDES THE RIGHT WAY ROUND FOR CM DIAGRAMS.

        """

        valy2=self.axis['y2'].get()
    
        if(self.limits[0] > self.limits[1]):
            self.ax1.set_xlim([self.limits[1],self.limits[0]])
        if(valy2 == "None"):
            if(self.limits[2] < self.limits[3]):
                self.ax1.set_ylim([self.limits[3],self.limits[2]])
        else:
            if(self.limits[2] > self.limits[3]):
                self.ax1.set_ylim([self.limits[3],self.limits[2]])

        self.limits=self.ax1.axis()


    #========================================================================

    #NOW ROUTINES FOR SAVING PLOTS TO GRAPHICS FILES. 

    def save_main(self):

        """
        
        SAVE THE MAIN PLOT TO AN IMAGE FILE. YOU NEED PIL INSTALLED TO USE JPEG/GIF FILES
            
        """

        #SET FOCUS TO THE PLOT
        self.canvas1._tkcanvas.focus_set()
    
        #GET FILE NAME
        datafile=tkFileDialog.asksaveasfilename()
    
        #SAVE FIGURE 
        if(datafile != ""):
            self.fig1.savefig(datafile)
            

    #========================================================================

    def save_sed(self):
            
        """
            
        SAVE THE SED PLOT TO AN IMAGE FILE. YOU NEED PIL INSTALLED TO USE JPEG/GIF FILES
            
        """


        #GET FILE NAME
        datafile=tkFileDialog.asksaveasfilename()
        #SET FOCUS TO THE PLOT
        self.canvas2._tkcanvas.focus_set()

        #SAVE FIGURE 

        if(datafile != ""):
            self.fig2.savefig(datafile)
        
    #========================================================================
    #SOME ROUTINES TO DO VARIOUS OVERPLOTS

    def get_arrow(self):

        """

        ROUTINE TO CALCULATE VALUES FOR AN EXTINCTION VECTOR.
        ???ADJUST FOR SIZE IF TOO BIG

        """

        #IF THERE IS ALREADY AN ARROW, REMOVE IT

        try: 
            self.arrow.remove()
        except:
            pass

        #GET WAVELENGTH CHOICES
        valx1=self.axis['x1'].get()
        valx2=self.axis['x2'].get()
        valy1=self.axis['y1'].get()
        valy2=self.axis['y2'].get()

        ##ONLY FOR A CC DIAGRAM, AND IF SHOWEXT SELECTED
        if((self.showext.get() != 1) | (valy2 == "None")):
            
            return

        #GET THE TWO EXTINCTION AMOUNTS, IN THE X AND Y DIRECTION

        self.ext1=self.extinct_law(self.waveband[valx1][1])-self.extinct_law(self.waveband[valx2][1])
        self.ext2=self.extinct_law(self.waveband[valy1][1])-self.extinct_law(self.waveband[valy2][1])
        
        #FIGURE OUT WHERE TO POSITION IT ON THE PLOT, BASED ON CURRENT LIMITS

        self.xstart=self.limits[0]+(self.limits[1]-self.limits[0])*0.1
        self.ystart=(self.limits[3]-self.limits[2])*0.8+self.limits[2]

        #GET THE USER PROVIDED AV, AND DRAW THE ARROW

        ##CHECK FOR VALID INPUT AND DISPLAY AN ERROR MESSAGE IF THERE IS NON-NUMERIC 
        ##INPUT OR A NEGATIVE VALUE

        message="Av must be a positive number."
        try:
            av=float(self.av.get())
            if(av <= 0):
                tkMessageBox.showerror("Error",message)
            else:
                self.arrow=self.ax1.arrow(self.xstart,self.ystart,self.ext1*av,self.ext2*av,head_width=0.05, head_length=0.1)
        except:
            tkMessageBox.showerror("Error",message)



    #========================================================================

    def make_limits(self):

        """
    
        ROUTINE TO READ AND PLOT USER SUPPLIED LIMITS AS A BOX. 
    
        IF A PARTICULAR LIMIT ISN'T SET, THE OTHER BOUNDARIES ARE EXPANDED TO THE EDGE OF THE PLOT

        """

        #IF WE'RE IN POSITION MODE, RETURN AND DON'T DRAW
        if(self.whichplot.get()==2):
            return

        #READ THE LIMITS

        xfmin=self.xfmin.get()
        xfmax=self.xfmax.get()
        yfmin=self.yfmin.get()
        yfmax=self.yfmax.get()

        #GO THROUGH THE VALUES. IF A VALID LIMIT IS GIVEN, CONVERT IT, 
        #OTHERWISE SET THE LIMITS TO THE EDGE OF THE PLOT, AND SET
        #THE VERT FLAG. IF THE VERT FLAG IS FALSE, DON'T PLOT THAT LINE

        try:
            xfmin=float(xfmin)
            vert1=True
        except:
            xfmin=float(self.limits[0])
            vert1=False
    
        try:
            xfmax=float(xfmax)
            vert2=True
        except:
            xfmax=float(self.limits[1])
            vert2=False
    
        try:
            yfmin=float(yfmin)
            vert3=True
        except:
            yfmin=float(self.limits[2])
            vert3=False
    
        try:
            yfmax=float(yfmax)
            vert4=True
        except:
            yfmax=float(self.limits[3])
            vert4=False
    
        #THIS IS A BIT KLUDGY - REMOVES THE PREVIOUS LINES, BUT 
        #CAN'T REMOVE A LINE IF IT HASN'T BEEN SET, SO YOU TRY/EXCEPT

        try:
            l=self.pvert1.pop(0)
            l.remove()
        except:
            pass

        try:
            l=self.pvert2.pop(0)
            l.remove()
        except:
            pass

        try:
            l=self.pvert3.pop(0)
            l.remove()
        except:
            pass

        try:
            l=self.pvert4.pop(0)
            l.remove()
        except:
            pass

        #NOW GO THROUGH EACH LIMIT - X AND Y MIN AND MAX. PLOT IF VERT FLAG IS SET

        if(vert1):
            self.pvert1=self.ax1.plot([xfmin,xfmin],[yfmin,yfmax],linestyle="--",color="black",marker="None",linewidth=2)
        if(vert2):
            self.pvert2=self.ax1.plot([xfmax,xfmax],[yfmin,yfmax],linestyle="--",color="black",marker="None",linewidth=2)
        if(vert3):
            self.pvert3=self.ax1.plot([xfmin,xfmax],[yfmin,yfmin],linestyle="--",color="black",marker="None",linewidth=2)
        if(vert4):
            self.pvert4=self.ax1.plot([xfmin,xfmax],[yfmax,yfmax],linestyle="--",color="black",marker="None",linewidth=2)


    #========================================================================
    #ROUTINES TO CONFIGURE THE MENUS DEPENDING ON CONTEXT

    def set_button_colour(self,x):

        """

        SET THE  COLOURS IN THE FILE MENUS TO THE PLOT COLOUR. THIS LETS THE MENU DOUBLE
        AS A LEGEND WITHOUT CLUTTERING UP THE PLOT.

        """


        for i in range(len(self.fileinfo["colmenu"])):
            self.fileinfo["colmenu"][i].config(bg=self.fileinfo["cols"][i].get())
            self.fileinfo["symmenu"][i].config(bg=self.fileinfo["cols"][i].get())

        for i in range(len(self.overinfo["colmenu"])):
            self.overinfo["colmenu"][i].config(bg=self.overinfo["cols"][i].get())
            self.overinfo["linemenu"][i].config(bg=self.overinfo["cols"][i].get())


    #========================================================================

    def update_choices(self):

        """
        A ROUTINE TO UPDATE THE DROPDOWN MENU FOR POTENTIAL WAVELENGTHS. 
        THIS WILL BE CALLED EACH TIME A NEW FILE IS LOADED

        """

        #SET LABELS TO FIRST ITEM IF THIS IS THE FIRST FILE LOADED

        if(self.loaded==0):
            self.axis['x1'].set(self.wavelist[0])
            self.axis['x2'].set(self.wavelist[0])
            self.axis['y1'].set(self.wavelist[0])
            self.axis['y2'].set(self.wavelist[0])
            self.loaded=1

        ##IDENTIFY THE MENU ITEMS

        menu1=self.axischoice1_x1['menu']
        menu2=self.axischoice1_x2['menu']
        menu3=self.axischoice2_y1['menu']
        menu4=self.axischoice2_y2['menu']

        ##ERASE THE PREVIOUS VALUES
        menu1.delete(0,'end')
        menu2.delete(0,'end')
        menu3.delete(0,'end')
        menu4.delete(0,'end')

        ##UPDATE TO THE NEW VALUES
        for wave in self.wavelist:
            menu1.add_command(label=wave,command=lambda wave=wave:self.axis['x1'].set(wave))
            menu2.add_command(label=wave,command=lambda wave=wave:self.axis['x2'].set(wave))
            menu3.add_command(label=wave,command=lambda wave=wave:self.axis['y1'].set(wave))
            menu4.add_command(label=wave,command=lambda wave=wave:self.axis['y2'].set(wave))

        ##ADD "NONE" VALUE FOR AT THE END OF THE SECOND Y VALUE, FOR CM DIAGRAMS
        menu4.add_command(label="None",command=lambda wave=wave:self.axis['y2'].set("None"))

    #========================================================================

    ##NOW THE VARIOUS PLOTTING ROUTINES


    def make_plot(self):

        """

        FIGURE OUT WHETHER WE'RE PLOTTING A CCM OR POSITION PLOT, 
        AND CALL THE RIGHT ROUTINE

        """

        whichplot=self.whichplot.get()
        if(whichplot == 1):
            self.ccm_plot()
        else:
            self.pos_plot()

    #========================================================================

    def pos_plot(self):


        """

        A ROUTINE TO PLOT A POSITION PLOT OF THE CATALOGUES. THIS IS USEFUL FOR SEEING
        WHERE A CHOSEN SED POINT IS LOCATED ON THE SKY.
   
        """

        ##INITIALIZE ERROR MESSAGE

        message="No valid data to plot."

        ##CLEAR THE FIGURE AND CREATE A NEW AXIS

        self.fig1.clear()
        self.ax1=self.fig1.add_subplot(111)

        ##GET THE CHOSEN WAVELENTHS AND UNCERTAINTY 

        ##NOW CYCLE THROUGH THE FILES
        j=0
        for file in self.filelist:

            ##CHECK TO SEE IF THE FILE IS SELECTED
            if(self.fileinfo["active"][j].get()=='1'):
          

                ##GET COLOURS AND SYMBOLS
                col=self.fileinfo["cols"][j].get()
                sym=self.symset[self.fileinfo["syms"][j].get()]
                scale=self.fileinfo["scale"][j].get()
                markersize=6.*self.symsize[self.fileinfo["syms"][j].get()]
                markerthick=0.5*self.symthick[self.fileinfo["syms"][j].get()]


                ##GET THE POSITIONS - CURRENTLY ONLY RECOGNIZES RA AND DEC 
                    
                valx=self.alldata[file]['ra']
                valy=self.alldata[file]['dec']

                self.ax1.plot(valx,valy,marker=sym,linestyle='None',color=col,markersize=markersize,markeredgewidth=markerthick)
                
            ##UPDATE THE COUNTER
            j=j+1

        self.ax1.set_xlabel('RA')
        self.ax1.set_ylabel('Dec')
        self.ax1.set_title(self.usertitle.get())
            
        ##PUT THE LIMITS INTO VARIABLES. WE KEEP TWO SETS, ONE FOR THE
        ##CURRENT LIMITS (WHICH THE USER CAN CHANGE) AND ONE FOR THE
        ##PLOT DEFAULTS.

        self.limits=self.ax1.axis()   ##CURRENT LIMITS
        self.olimits=self.ax1.axis()  ##ORIGINAL LIMITS

        #SET THE MARKUP POINT. IF IT IS ALREADY DEFINED, PLOT IT.
        #IF IT HASN'T BEEN DEFINED YET, DEFINE A DUMMY VALUE, AND SET TO AN 
        #UNSEEABLE POINT




        try:

            xx=self.markervals['xpos']
            yy=self.markervals['ypos']

            self.markup=self.ax1.plot([xx],[yy],marker='o',markersize=10,color="black")

        except:
            self.markup=self.ax1.plot([valx[0]],[valy[0]],marker='.',markersize=0,color="black")


        ##DISPLAY THE IMAGE

        self.canvas1.draw()

    #========================================================================

    def ccm_plot(self):


        """

        A ROUTINE TO PLOT THE COLOUR-COLOUR, OR COLOUR-MAGNITUDE DIAGRAM, FOR THE SELECTED
        FILES
   
        """

        ##INITIALIZE ERROR MESSAGE

        message="No valid data to plot."

        ##CLEAR THE FIGURE AND CREATE A NEW AXIS

        self.fig1.clear()
        self.ax1=self.fig1.add_subplot(111)

        ##GET THE CHOSEN WAVELENTHS AND UNCERTAINTY 

        valx1=self.axis['x1'].get()
        valx2=self.axis['x2'].get()
        valy1=self.axis['y1'].get()
        valy2=self.axis['y2'].get()
        showuncert=self.uncert.get()

        isplot=0  ##FLAG FOR SUCCESSFUL PLOT. IF THE WRONG COMBINATION OF FLUXES IS CHOSEN 
                  ##IT'S POSSIBLE TO NOT HAVE A VALID PLOT

        ##NOW CYCLE THROUGH THE FILES
        j=0
        for file in self.filelist:

            ##CHECK TO SEE IF THE FILE IS ACTIVE
            if(self.fileinfo["active"][j].get()=='1'):
          
                ##FOR EACH FILE, ONLY PLOT IF IT CONTAINS THE APPROPRIATE WAVELENGTHS

                try:
                #if(0==0):

          
                    ##GET COLOURS AND SYMBOLS
                    col=self.fileinfo["cols"][j].get()
                    sym=self.symset[self.fileinfo["syms"][j].get()]
                    scale=self.fileinfo["scale"][j].get()
                    markersize=6.*self.symsize[self.fileinfo["syms"][j].get()]
                    markerthick=0.5*self.symthick[self.fileinfo["syms"][j].get()]
 
                    ##CALCULATE THE COLOURS AND ERRORS FOR THIS FILE
          
                    valx=self.alldata[file][valx1]['mag']-self.alldata[file][valx2]['mag']
                    errx=sqrt(self.alldata[file][valx1]['merr']**2+self.alldata[file][valx2]['merr']**2)

                    ##CASE OF CC DIAGRAM - CALCUATE COLOUR, OTHERWISE JUST HAVE MAGNITUDE

                    if(valy2 != "None"):
                        valy=self.alldata[file][valy1]['mag']-self.alldata[file][valy2]['mag']
                        erry=sqrt(self.alldata[file][valy1]['merr']**2+self.alldata[file][valy2]['merr']**2)
                        ##CASE OF CM DIAGRAM
                    else:
                        valy=self.alldata[file][valy1]['mag']
                        erry=self.alldata[file][valy1]['merr']
 
                    ##NOW PLOT THE POINTS
             
                    self.ax1.plot(valx,valy,marker=sym,linestyle='None',color=col,markersize=markersize,markeredgewidth=markerthick)
                    
                    ##PLOT UNCERTAINTIES, IF DESIRED
                    if(showuncert):
                        self.ax1.errorbar(valx,valy,xerr=errx,color=col,yerr=erry,linestyle="None")
                        
                        ##FOR CM DIAGRAM, REVERSE THE AXIS LIMITS TO SHOW FAINT SOURCES AT BOTTOM
                        if(valy2 == "None"):
                            self.ax1.set_ylim([self.ax1.axis()[3],self.ax1.axis()[2]])

                    #NOW WE HAVE A SUCCESSFUL PLOT
                    isplot=1

                    
                ##IF THERE IS NO APPROPRIATE COMBINATION OF WAVELENGTHS IN THE LOADED CATALOGUES
                ##SET THE ERROR MESSAGE

                except:

                    message="There are no data sets which contain this combination of wavelengths."
            
            ##UPDATE THE COUNTER
            j=j+1

        ##CHECK IF WE HAVE A VALID PLOT. IF NOT, PRINT ERROR, AND EXIT
        if(not isplot):
            tkMessageBox.showerror("Error",message)
            return

        ##NOW ADD THE X AND Y LABELS

        self.ax1.set_xlabel(self.waveband[valx1][0]+" - "+self.waveband[valx2][0])
        self.ax1.set_title(self.usertitle.get())
            
        
        #CASES FOR CM AND CC DIAGRAM
        if(valy2 != "None"):
            self.ax1.set_ylabel(self.waveband[valy1][0]+" - "+self.waveband[valy2][0])
        else:
            self.ax1.set_ylabel(self.waveband[valy1][0])
          

        ##PUT THE LIMITS INTO VARIABLES. WE KEEP TWO SETS, ONE FOR THE
        ##CURRENT LIMITS (WHICH THE USER CAN CHANGE) AND ONE FOR THE
        ##PLOT DEFAULTS. THIS IS USED DURING ZOOMING AND UNZOOMING

        self.limits=self.ax1.axis()   ##CURRENT LIMITS
        self.olimits=self.ax1.axis()  ##ORIGINAL LIMITS

       
        #PLOT EXTINCTION ARROW, IF NEEDED

        self.get_arrow()

        #SET MARKUP POINT. IF DEFINED, PLOT, IF NOT DEFINED, DEFINED A DUMMY VALUE AND 
        #PLOT USING AN INVISIBLE POINT

        try:
                 
            if((self.axis['x1'].get() in self.markervals.keys()) & (self.axis['x2'].get() in self.markervals.keys()) & (self.axis['y1'].get() in self.markervals.keys()) & (self.axis['y2'].get() in self.markervals.keys())):

                xx=self.markervals[self.axis['x1'].get()]-self.markervals[self.axis['x2'].get()]
                yy=self.markervals[self.axis['y1'].get()]-self.markervals[self.axis['y2'].get()]

                self.markup=self.ax1.plot([xx],[yy],marker='o',markersize=10,color="black")

        except:

            self.markup=self.ax1.plot([valx[0]],[valy[0]],marker='.',markersize=0,color="black")

            

        #DRAW BOX
        self.make_limits()

        ##DISPLAY THE IMAGE

        self.canvas1.draw()

        #IF THERE ARE OVERPLOTS, NOW PLOT THEMS

        if(self.allover !={}):
            self.oplot_over()

    #========================================================================

    def get_sed(self):
        
        """
      
        CALCULATES THE DISTANCE FROM THE CLICKED ON POINT TO THE NEAREST
        DATA POINT (IN ANY FILE), AND PLOTS THE SED IN THE SED WINDOW

        """
        showuncert=self.uncert.get()

        ##INITIALIZE THE DISTANCE TO A LARGE VALUE

        d=1000000.

        ##GET THE WAVELENGTHS

        valx1=self.axis['x1'].get()
        valx2=self.axis['x2'].get()
        valy1=self.axis['y1'].get()
        valy2=self.axis['y2'].get()


        try:
            float(self.xo)+float(self.yo)

            pass
        except:
            try:
                l=self.markup.pop(0)
                l.remove()
                self.canvas1.draw()
                self.fig2.clear()
                self.canvas2.draw()

            except:
                pass

            return

        ##GO THROUGH EACH FILE. CALCULATE THE COLOURS, AND THEN CYCLE THROUGH TO 
        ##COMPARE DISTANCES. IF THE DISTANCE IS SMALLER THAN THE PREVIOUS LOW VALUE,
        ##UPDATE THE NUMBER AND FILE NAME. NOTE THAT THIS WILL NOT DISTINGUISH TWO
        ##POINTS WITH EXACTLY THE SAME COLOURS??
        self.markervals={}
        self.markervals['None']=0

        #CYCLE THROUGH THE FILES
        for file in self.filelist:

            #GET THE COLOURS/MAGNITUDES AND POSITIONS

            c1=self.alldata[file][valx1]['mag']-self.alldata[file][valx2]['mag']
            if(valy2 != "None"):
                c2=self.alldata[file][valy1]['mag']-self.alldata[file][valy2]['mag']
            else:
                c2=self.alldata[file][valy1]['mag']

            valx=self.alldata[file]['ra']
            valy=self.alldata[file]['dec']

            ##THE CC/CM PLOT VERSION
            #CYCLE THROUGH THE POINTS, CALCULATE DISTANCE TO THE MOUSE CLICK,
            #AND SEE IF IT IS LOWER THAN THE CURRENT NEAREST POINT

            if(self.whichplot.get()==1):

 
                for i in range(len(valx)):
                    dist=sqrt((self.xo-c1[i])**2+(self.yo-c2[i])**2)

                    #IF CLOSER, SET THE VALUES
                    if(dist < d):
                        fname=file
                        num=i
                        d=dist
                        self.markervals['xpos']=valx[num]
                        self.markervals['ypos']=valy[num]
                        #self.markpos1=valx[num]
                        #self.markpos2=valy[num]
                        #self.markc1=c1[num]
                        #self.markc2=c2[num]

            ##THE POSITION PLOT VERSION - THE SAME THING, BUT IN POSITION UNITS
            if(self.whichplot.get()==2):

 
                for i in range(len(valx)):
                    dist=sqrt((self.xo-valx[i])**2+(self.yo-valy[i])**2)
                    if(dist < d):
                        fname=file
                        num=i
                        d=dist
                        self.markervals['xpos']=valx[num]
                        self.markervals['ypos']=valy[num]

                        #self.markpos1=valx[num]
                        #self.markpos2=valy[num]
                        #self.markc1=c1[num]
                        #self.markc2=c2[num]
                        

        ##REMOVE THE PREVIOUS MARK, AND THEN MARK THE CHOSEN POINT ON THE CC/CM DIAGRAM
                    
        
        


        #ERASE THE SED PLOT AND CREATE NEW AXIS EVENT TO REPLOT
      
        self.fig2.clear()
        self.ax2=self.fig2.add_subplot(111)

        #INITIALIZE THE VARIABLES TO HOLD THE SED (SO WE CAN GET A LINE PLOT AT THE END)
      
        ww=[]
        vv=[]
        ee=[]
      
        ##PLOT A POINT FOR EACH WAVELENGTH. CALCULATE LAMBAFLAMB OR NUFNU FOR A PROPER SED PLOT

        for wave in self.wavelist:

            ##IS THERE AN ENTRY FOR THIS WAVELENGTH?
            try:
            #if(0==0):

                ##CALCULATE VALUES, APPEND TO THE SED.
                lamflam=self.alldata[fname][wave]['flux'][num]*1e-23*2.997924e10/(self.waveband[wave][1]*1e-4)
                self.markervals[wave]=self.alldata[fname][wave]['mag'][num]

                vv.append(lamflam)
                ww.append(self.waveband[wave][1])
                ee.append(self.alldata[fname][wave]['ferr'][num]*1e-23*2.997924e10/(self.waveband[wave][1]*1e-4))

                ##IF NOT, SKIP IT
            except:
                pass

            ##SET THE AXIS LABELS 

        self.ax2.set_xlabel(r'$\lambda$ ($\mu$m)')
        self.ax2.set_ylabel(r'$\lambda$ F($\lambda$) (erg cm$^{-2}$ s$^{-1}$ Hz$^{-1}$)')
        self.ax2.set_title(self.alldata[fname]['label'][num])

        ##MUTUALLY SORT BY THE WAVELENGTH
        ww,vv,ee = zip(*sorted(zip(ww,vv,ee)))


        ##PLOT POINTS AND LINE
        self.ax2.plot(ww,vv,color='black',marker="d")
        
        if(showuncert):
            self.ax2.errorbar(ww,vv,color='black',yerr=ee,linestyle="None")


        ##??? ADD UNCERTAINTIES
        
        ##LOG SCALES
        self.ax2.set_yscale('log')
        self.ax2.set_xscale('log')

        try:
            l=self.markup.pop(0)
            l.remove()
        except:
            pass


        if((self.whichplot.get()==1)):
            if((self.axis['x1'].get() in self.markervals.keys()) & (self.axis['x2'].get() in self.markervals.keys()) & (self.axis['y1'].get() in self.markervals.keys()) & (self.axis['y2'].get() in self.markervals.keys())):

               xx=self.markervals[self.axis['x1'].get()]-self.markervals[self.axis['x2'].get()]
               yy=self.markervals[self.axis['y1'].get()]-self.markervals[self.axis['y2'].get()]

        if(self.whichplot.get()==2):
             xx=self.markervals['xpos']
             yy=self.markervals['ypos']

        self.markup=self.ax1.plot([xx],[yy],marker='o',markersize=10,color="black")

        #THIS KEEPS THE LABELS FROM BEING CUT OFF
        self.fig2.tight_layout()

        ##AND DISPLAY BOTH PLOTS
        self.canvas2.draw()
        self.canvas1.draw()
      
    #========================================================================

    def oplot_over(self):

        """

        ROUTINE TO PLOT A USER PROVIDED OVERPLOT. THIS WORKS PRETTY MUCH THE SAME
        WAY AS THE CCM PLOTTING ROUTINE, EXCEPT THAT IT PLOTS A LINE RATHER THAN 
        A SERIES OF POINTS

        """

        ##GET THE CHOSEN WAVELENTHS 
                
        valx1=self.axis['x1'].get()
        valx2=self.axis['x2'].get()
        valy1=self.axis['y1'].get()
        valy2=self.axis['y2'].get()

        isplot=0  ##FLAG FOR SUCCESSFUL PLOT. IF THE WRONG COMBINATION OF FLUXES IS 
                  ##CHOSEN IT'S POSSIBLE TO NOT HAVE A VALID PLOT

        ##NOW CYCLE THROUGH THE FILES
        j=0

        for file in self.overfilelist:

            ##CHECK TO SEE IF THE FILE IS ACTIVE
            if(self.overinfo["active"][j].get()==1):

                ##FOR EACH FILE, ONLY PLOT IF IT CONTAINS THE APPROPRIATE WAVELENGTHS
                #try:
                if(0==0):

          
                    ##GET COLOURS AND SYMBOLS
                    col=self.overinfo["cols"][j].get()
                    line=self.overinfo["lines"][j].get()

                    #??? WE WANT SCALE FOR THIS
                    scale=self.overinfo["scale"][j].get()
          
                    ##CALCULATE THE COLOURS AND ERRORS FOR THIS FILE
          
                    valx=self.allover[file][valx1]['mag']-self.allover[file][valx2]['mag']

                    print "DD",valy1,valy2
                    ##CASE OF CC DIAGRAM
                    if(valy2 != "None"):
                        valy=self.allover[file][valy1]['mag']-self.allover[file][valy2]['mag']
                        ##CASE OF CM DIAGRAM
                    else:
                        valy=self.allover[file][valy1]['mag']
 
                    ##NOW PLOT THE CURVE

                    self.ax1.plot(valx,valy,linestyle=line,color=col)
                        
                    ##SKIP IT IF THERE IS NO POINTS AVAILABLE
                    isplot=1

                #except:
                #    #pass
                #    message="There is not a valid overplot at these wavelengths."
            
            ##UPDATE THE COUNTER
            j=j+1

        ##IF THERE IS NO SUCCESSFUL PLOT, GIVE ERROR MESSAGE
        if(not isplot):
            tkMessageBox.showerror("Error",message)

        ##AND DISPLAY
        self.canvas1.draw()

    #========================================================================

    def placeholder(self):
    
        ##DO NOTHING ROUTINE TO LINK TO BUTTONS WHERE THE FUNCTION HASN'T 
        ##BEEN WRITTEN YET

        pass

    #========================================================================

    
    ##NOW SOME ROUTINES TO CREATE THE MENUS/LEGENDS FOR THE CATALOGUES AND
    ##OVERPLOT FILES

    def add_row(self):
  
        """
   
        ROUTINE TO ADD AN ENTRY TO THE CATALOGUE FILE LIST 

        """


        ##TRACK CURRENT ROW
        self.m_currentRow = self.m_currentRow+1
    
        ##APPEND A NEW VARIABLE TO EACH OF THE LISTS - SYMBOL, COLOURS, ACTIVE, AND SCALE.

        self.fileinfo["syms"].append(StringVar())
        self.fileinfo["cols"].append(StringVar())   
        self.fileinfo["active"].append(StringVar())
        self.fileinfo["scale"].append(StringVar())
        self.fileinfo["files"].append(StringVar())

        ##WE NEED TO KEEP TRACK OF THE MENU ITEMS, TO QUERY AND CHANGE AS NEEDED. 
        ##SO WE WILL APPEND EACH FRAME INSTANCE AND MENU ITEM TO A LIST

        ##SET BOUNDING FRAME
        self.fileinfo["filewind"].append(Frame(self.fileframe))

        ##NOW SET UP THE INDIVIDUAL MENUES

        ##BUTTON TO CHOOSE IF THE FILE IS ACTIVE
        self.fileinfo["activemenu"].append(Checkbutton(self.fileinfo["filewind"][self.fileinfo["nfiles"]],variable=self.fileinfo["active"][self.fileinfo["nfiles"]]))
        self.fileinfo["activemenu"][self.fileinfo["nfiles"]].grid(row=0,column=1)
        
        #NAME OF THE FILE
        self.fileinfo["filelabel"].append(Label(self.fileinfo["filewind"][self.fileinfo["nfiles"]],textvariable=self.fileinfo["files"][self.fileinfo["nfiles"]],width=27))
        self.fileinfo["filelabel"][self.fileinfo["nfiles"]].grid(row=0,column=2,sticky=W)

        #DROP DOWN MENU FOR COLOUR
        self.fileinfo["colmenu"].append(OptionMenu(self.fileinfo["filewind"][self.fileinfo["nfiles"]],self.fileinfo["cols"][self.fileinfo["nfiles"]],
                                                   'red',
                                                   'orange',
                                                   'yellow',
                                                   'green',
                                                   'turquoise',
                                                   'blue',
                                                   'magenta',
                                                   'black',command=self.set_button_colour))
        self.fileinfo["colmenu"][self.fileinfo["nfiles"]].grid(row=0,column=3)
        self.fileinfo["cols"][self.fileinfo["nfiles"]].set('red')
        self.fileinfo["colmenu"][self.fileinfo["nfiles"]].config(bg=self.fileinfo["cols"][self.fileinfo["nfiles"]].get(),width=12)
   
        ##DROP DOWN MENU FOR SYMBOLS FOR PLOTTING, IN UTF-8 FORMAT
        self.fileinfo["symmenu"].append(OptionMenu(self.fileinfo["filewind"][self.fileinfo["nfiles"]],self.fileinfo["syms"][self.fileinfo["nfiles"]],
                                                   u'\u25FC',
                                                   u'\u25C6',
                                                   u'\u25CF',
                                                   u'\u2605',
                                                   u'\u29EB',
                                                   'x',
                                                   '+'))
        self.fileinfo["symmenu"][self.fileinfo["nfiles"]].grid(row=0,column=4)
        self.fileinfo["symmenu"][self.fileinfo["nfiles"]].config(bg=self.fileinfo["cols"][self.fileinfo["nfiles"]].get(),width=4)
    
        #MENU FOR SCALE VALUE FOR CM DIAGRAMS

        self.fileinfo["scalemenu"].append(Entry(self.fileinfo["filewind"][self.fileinfo["nfiles"]],textvariable=self.fileinfo["scale"][self.fileinfo["nfiles"]],width=5).grid(row=0,column=5))


        ##SET DEFAULT VALUES

        self.fileinfo["syms"][self.fileinfo["nfiles"]].set(u'\u25FC')
        self.fileinfo["active"][self.fileinfo["nfiles"]].set(1)
        self.fileinfo["scale"][self.fileinfo["nfiles"]].set('1')
                         
        self.fileinfo["filewind"][self.fileinfo["nfiles"]].grid(row=self.m_currentRow,column=0,sticky=W)
        for i in range(len(self.filelist)):
            self.fileinfo["files"][i].set(self.filelist[i])

        ##UPDATE NUMBER OF FILES
        self.fileinfo["nfiles"] = self.fileinfo["nfiles"] + 1

    #========================================================================

    def add_row_over(self):
  
        """
   
        ROUTINE TO ADD AN ENTRY TO THE FILE LIST.

        """

        ##TRACK CURRENT ROW
        self.n_currentRow = self.n_currentRow+1
    
        ##APPEND A NEW VARIABLE TO EACH OF THE LISTS - LINE, COLOURS, ACTIVE

        self.overinfo["lines"].append(StringVar())
        self.overinfo["cols"].append(StringVar())   
        self.overinfo["active"].append(IntVar())
        self.overinfo["files"].append(StringVar())
        self.overinfo["scale"].append(StringVar())

        ##WE NEED TO KEEP TRACK OF THE MENU ITEMS, TO QUERY AND CHANGE AS NEEDED. 
        ##SO WE WILL KEEP LISTS OF FRAME INSTANCES, AND OF THE MENU ITEMS. 

        ##SET BOUNDING FRAME
        self.overinfo["filewind"].append(Frame(self.fileframe1))

        ##NOW SET UP THE INDIVIDUAL MENUES

        ##BUTTON TO CHOOSE IF THE FILE IS ACTIVE
        self.overinfo["activemenu"].append(Checkbutton(self.overinfo["filewind"][self.overinfo["nfiles"]],variable=self.overinfo["active"][self.overinfo["nfiles"]]))
        self.overinfo["activemenu"][self.overinfo["nfiles"]].grid(row=0,column=1)
        
        #NAME OF THE FILE
        self.overinfo["filelabel"].append(Label(self.overinfo["filewind"][self.overinfo["nfiles"]],textvariable=self.overinfo["files"][self.overinfo["nfiles"]],width=27))
        self.overinfo["filelabel"][self.overinfo["nfiles"]].grid(row=0,column=2,sticky=W)

        #DROP DOWN MENU FOR COLOUR
        self.overinfo["colmenu"].append(OptionMenu(self.overinfo["filewind"][self.overinfo["nfiles"]],self.overinfo["cols"][self.overinfo["nfiles"]],
                                                   'red',
                                                   'orange',
                                                   'yellow',
                                                   'green',
                                                   'turquoise',
                                                   'blue',
                                                   'magenta',
                                                   'black',command=self.set_button_colour))
        self.overinfo["colmenu"][self.overinfo["nfiles"]].grid(row=0,column=3)
        self.overinfo["cols"][self.overinfo["nfiles"]].set('red')
        self.overinfo["colmenu"][self.overinfo["nfiles"]].config(bg=self.overinfo["cols"][self.overinfo["nfiles"]].get(),width=12)
   
        ##DROP DOWN MENU FOR LINES FOR PLOTTING
        self.overinfo["linemenu"].append(OptionMenu(self.overinfo["filewind"][self.overinfo["nfiles"]],self.overinfo["lines"][self.overinfo["nfiles"]],
                                                    "-",
                                                    "--",
                                                    "-."))
        self.overinfo["linemenu"][self.overinfo["nfiles"]].grid(row=0,column=4)
        self.overinfo["linemenu"][self.overinfo["nfiles"]].config(bg=self.overinfo["cols"][self.overinfo["nfiles"]].get(),width=4)
    
    
        #MENU FOR SCALE VALUE FOR CM DIAGRAMS

        self.overinfo["scalemenu"].append(Entry(self.overinfo["filewind"][self.overinfo["nfiles"]],textvariable=self.overinfo["scale"][self.overinfo["nfiles"]],width=5).grid(row=0,column=5))

        ##SET DEFAULT VALUES

        self.overinfo["lines"][self.overinfo["nfiles"]].set('-')
        self.overinfo["active"][self.overinfo["nfiles"]].set(1)
        self.overinfo["scale"][self.overinfo["nfiles"]].set('1')
             
        self.overinfo["filewind"][self.overinfo["nfiles"]].grid(row=self.n_currentRow,column=0,sticky=W)
        for i in range(len(self.overfilelist)):
            self.overinfo["files"][i].set(self.overfilelist[i])

        ##UPDATE NUMBER OF FILES
        self.overinfo["nfiles"] = self.overinfo["nfiles"] + 1

    #========================================================================

    ##ROUTINES TO READ IN CATALOGUE FILES AND OVERPLOT FILES
    
    def choose_input(self):

        """
        
        FIGURE OUT WHAT TYPE OF FILE IS DESIRED, AND THEN CALL THE RIGHT ROUTINE

        """

        if(self.filetype.get()=="Text"):
            self.read_text_file()
        elif(self.filetype.get()=="IRSA"):
            self.read_irsa_file()
        elif(self.filetype.get()=="SDSS"):
            self.read_sdss_file()


    #========================================================================
    def read_sdss_file(self):
        
        """ROUTINE TO READ AN SDSS FILE. SDSS FILES CAN GET PRETTY COMPLICATED: THIS ASSUMES
        THAT THE NAMES OF THE COLUMN HEADERS HAVEN'T CHANGED, AND THAT IT'S IN THE FAIRLY
        STANDARD FORMAT. 

        THE SDSS ROUTINE CONVERTS FROM THE SDSS INTERNAL UNITS
        (LUPTITUDES AND NANOMAGGIES) TO AB MAGNITUDES AND JY, TO MATCH
        OTHER SYSTEMS. SEE ??? FOR DETAILS OF THIS CONVERSION PROCESS.

        THE ASSUMPTION IS MADE THAT ALL FIVE WAVELENGTHS WILL BE IN THE CATALOGUE FILE.

        """

        newfile={}
        
        ##USER QUERY FOR FILE
        self.datafile=tkFileDialog.askopenfilename()
        
        ##IF NO FILE CHOSEN, EXIT WITHOUT DOING ANYTHING
        if(self.datafile == ""):
            return

        infile=0     ##FLAG FOR WHICH LINE OF THE FILE
        npoint=0     ##NUMBER OF POINTS
        localwave=[] ##VARIABLE WITH THE WAVELENGHTS FOR THIS FILE
        unitlist=[]  ##UNITS TO GO WITH LOCALWAVE, FOR CONVERSIONS


        ##SET SOME BASIC VARIABLES 

        corrfac=[-0.04,0,0,0,0.02]   ##CORRECTION FACTORS FOR AB MAGNITUDES
       
        ontable=0  #FLAG TO SEE IF IN RIGHT PART OF FILE



        ##SET UP THE DICTIONARY TO HOLD THE INFORMATION. 

        sdss_label={}
        sdss_err={}
        sdss_choice={}
        sdss_errchoice={}
        self.npoints=0
        for wave in self.sdss_waves:
            sdss_label[wave]=[]
            sdss_err[wave]=[]
            sdss_choice[wave]=[]
            sdss_errchoice[wave]=[]
            self.wavelist.append(wave)

        #FIRST WE WILL CYCLE THROUGH THE FILE TO FIGURE OUT THE NUMBER OF ELEMENTS. 
        #FOR EACH LINE IN THE FILE

        for line in open(self.datafile):

            ##FOUND THE RIGHT SECTION OF THE FILE
            if(("Table1" in line)):
                ontable=1

            ##ENTERING THE WRONG SECTION OF THE FILE
            elif(("Table" in line) & ("Table1" not in line)):
                ontable=0

            ##IN THE RIGHT SECTION OF THE FILE, CAN DO THE PARSING
            elif(("Table" not in line) & (ontable==1)):

                if(infile==0):
                    ##FIRST LINE HAS WAVEBANDS
                    names=line.split(',')
                    infile=1

                    for item in names:

                        item=item.rstrip()


                        ##LOOK FOR POSSIBLE FLUX/ERR COLUMNS AND ASSEMBLE A LIST. FLUXES HAVE 
                        ##FLUX OR MAG IN THE NAME, ERRORS ALSO HAVE ERR.
                        for wave in self.sdss_waves:

                            #CONSTRUCT THE LABEL
                            labind="_"+wave
                            errind="Err_"+wave

                            #SIMPLE LABELS
                            if(item == wave):
                                sdss_label[wave].append(item)
 
                            #MORE COMPLEX LABELS
                            elif((("Mag" in item) | ("Flux" in item))  & ("Err" not in item) & (labind in item)):
                                sdss_label[wave].append(item)
    
                            #SIMPLE ERROR LABEL
                            if(item == errind):
                                sdss_err[wave].append(item)

                            #MORE COMPLEX ERROR LABELS
                            elif((("Mag" in item) | ("Flux" in item))  & ("Err" in item) & (labind in item)):
                                sdss_err[wave].append(item)


                else:
                    ##THIS IS A FLUX POINT, COUNT IT.
                    self.npoints=self.npoints+1

        self.sdss_choice={}
        self.sdss_errchoice={}
        for wave in self.sdss_waves:
            sdss_label[wave].append('None')
            sdss_err[wave].append('None')
            self.sdss_choice[wave]=StringVar()
            self.sdss_errchoice[wave]=StringVar()
            
        ##CLOSE THE FILE

        close(self.datafile)


        ##NOW WE NEED TO MAKE A POP-UP WINDOW FOR THE LIST OF FILES.
        ##MOVE THIS TO A SEPARATE CLASS???

        self.top=Toplevel(self) 

        self.top.title('Select Columns')

        #SETUP THE WINDOW BASED ON COLUMNS. ATTACH A SCROLLBAR FOR LONG LISTS
    
        #FIRST SET UP THE FRAME AND THE SCROLLBAR, AND ATTACH TO A CANVAS
        self.sdss_window=Frame(self.top)
 
        #TOP LINE OF CHOICES - PS NAME, EXIT BUTTON
        lab0=Button(self.sdss_window,text='Load Values and Close',command=self.sdss_readquit).grid(row=0,column=0)
        lab1=Button(self.sdss_window,text='Load Preset',command=self.sdss_load_preset).grid(row=0,column=1)
        lab1=Button(self.sdss_window,text='Save Preset',command=self.sdss_save_preset).grid(row=0,column=2)
        lab1=Button(self.sdss_window,text='Cancel',command=self.top.destroy).grid(row=0,column=3)
    
    
        #LABELS FOR COLUMNS
        lab1=Label(self.sdss_window,text="Flux",width=20).grid(row=1,column=0)
        lab2=Label(self.sdss_window,text="Uncertainty").grid(row=1,column=1)
  
        #NOW CYCLE THROUGH LIST. ONE ITEM FOR EACH POTENTIAL FLUX COLUMN, DROP DOWN MENU CONTAINS ALL THE 
        #POTENTIAL VALUES. 
        
        i=2
        for wave in self.sdss_waves:
            choice1=OptionMenu(self.sdss_window,self.sdss_choice[wave],*sdss_label[wave])
            choice1.config(width=12)
            choice1.grid(row=i,column=0)
            choice1=OptionMenu(self.sdss_window,self.sdss_errchoice[wave],*sdss_err[wave])
            choice1.config(width=12)
            choice1.grid(row=i,column=1)
            i=i+1
            self.sdss_choice[wave].set(sdss_label[wave][0])
            self.sdss_errchoice[wave].set(sdss_err[wave][0])

        self.sdss_window.grid(row=0,column=0)
 
        #GET A LIST OF SORTED WAVELENGTHS

        self.wavelist=list(set(self.wavelist))
        sortwave=[]
        for wave in self.wavelist:
            sortwave.append(self.waveband[wave][1])
        
        self.wavelist=list(zip(*sorted(zip(sortwave,self.wavelist)))[1])

        #THE WINDOW CALLS SDSS_READQUIT, WHICH READS THE FILE, AND THEN CLOSES

    #========================================================================

    def sdss_readquit(self):

        """
    
        ROUTINE READ CHOSEN COLUMNS FROM AN SDSS FILE, AS SELECTED IN THE PREVIOUS ROUTINE

        """
              

        infile=0   #FLAG FOR WHERE IN THE FILE
        ipoint=0   #COUNTER FOR CURRENT POINT

        #SET UP VARIABLES - NUMPY ARRAY FOR MAGNITUDES AND THEIR ERRORS, FLUXES AND THERE ERRORS, 
        #A LIST FOR UPPER/LOWER LIMIT FLAG AND LABELS OF POINTS 

        #LIST OF LOCAL WAVELENGTHS

        #DICTIONARIES TO HOLD THE FLUXES/ERRORS ETC. 

        newfile={}

        flux={}   #FLUX
        ferr={}   #FLUX ERROS
        mag={}    #MAGNITUDES
        merr={}   #MAGNITUDE ERRORS
        ind={}    #KEEPING TRACK ???
        errind={}

        xpos=[]   #LIST OF X POSITIONS
        ypos=[]   #LIST OF Y POSITIONS
        labels=[] #LIST OF SOURCE NAMES

        calib=3631.    ##CALIBRATION FOR AB MAGNITUDES

        ##SET UP THE ARRAYS FOR THE DATA, ONE FOR EACH WAVELENGTH
        for wave in self.sdss_waves:
            flux[wave]=zeros(self.npoints)
            ferr[wave]=zeros(self.npoints)
            mag[wave]=zeros(self.npoints)
            merr[wave]=zeros(self.npoints)

        ##READ THE DATA INTO THE ARRAY - CYCLE THROUGH AS BEFORE, BUT NOW ADD
        ##INSTEAD OF SIMPLY COUNTING

        ###COUNTERS AS BEFORE
        for line in open(self.datafile):

            ##FOUND THE RIGHT SECTION OF THE FILE
            if(("Table1" in line)):
                ontable=1

            ##ENTERING THE WRONG SECTION OF THE FILE
            elif(("Table" in line) & ("Table1" not in line)):
                ontable=0

            ##CASE FOR BLANK LINE - IGNORE
            elif(line.strip() == ""):
                pass

            ##IN THE RIGHT SECTION OF THE FILE, CAN DO THE PARSING
            elif(("Table" not in line) & (ontable==1)):

                ##IF THIS IS THE FIRST LINE OF THE SECTION, GET THE COLUMNS WHERE THE FLUXES/MAGNITUDES/OBJID ARE

                if(infile==0):
                    ##FIRST LINE HAS WAVEBANDS
                    names=line.split(',')
                    infile=1
                    i=0
                    for item in names:

                        item=item.rstrip()   ##STRIP OFF NEWLINE CHARACTERS, IF APPLICABLE

                        ##CHECK FOR OBJECT ID
                        if(item == "objid"):
                            ind['obj']=i

                        ##POSITIONS
                        if(item.lower() == "ra"):
                            ind['ra']=i
                        if(item.lower() == "dec"):
                            ind['dec']=i


                        ##GET THE CHOSEN WAVELENGTH, COMPARE IT TO LIST ITEM, FOR ERROR AND WAVELENGTH
                        for wave in self.sdss_waves:

                            if((item == self.sdss_choice[wave].get()) & (self.sdss_choice[wave] != "None")):
                                ind[wave]=i
                            if(item == self.sdss_errchoice[wave].get()):
                                errind[wave]=i
                        i=i+1

                else:
                    names=line.split(',')

                    #GET THE LABELS AND X AND Y POSITIONS

                    labels.append(names[ind['obj']])
                    xpos.append(names[ind['ra']])
                    ypos.append(names[ind['dec']])
                
                    #GET THE FLUX AND WAVELENGTHS

                    for wave in self.sdss_waves:

                        ##FIRST, CHECK FOR LUPTITUDES. THIS IS TRUE IF THE SIMPLE LABELS ARE USED,
                        ##OR THE LABEL CONTAINS 'MAG'

                        if((self.sdss_choice[wave].get()==wave) | ("Mag" in self.sdss_choice[wave].get())):

                            #MAGNITUDE VERSION - CALCULATE FLUX

                            ##WE HAVE LUPTITUDES AND LUPTITUDE ERRORS
                            
                            lup=float(names[ind[wave]])
                            luperr=float(names[errind[wave]])

                            if(lup < -99):
                                nmgy=numpy.nan
                                ivar=0
                            else:
                                ##CONVERT TO NANOMAGGIES AND IVAR (FLUX VERSION)
                                nmgy=self.sdss_b[wave]/5.*sinh(-lup*log(10)/2.5-log(self.sdss_b[wave]))
                                ivar=self.sdss_b[wave]/5.*cosh(-lup*log(10)/2.5-log(self.sdss_b[wave]))*luperr*log(10)/2.5

                        elif("Flux" in self.sdss_choice[wave].get()):

                            #FLUX VERSON - WE HAVE NANOMAGGIES AND IVAR, CONVERT TO FLUX

                            nmgy=float(names[ind[wave]])
                            ivar=float(names[errind[wave]])

                        #CASE FOR NO DETECTION
                        if(ivar==0):
                            ff=nan
                            fe=nan
                            mm=nan
                            me=nan

                        else:

                            ff=3.631e-6*nmgy*10**(-0.4*self.sdss_abfix[wave])
                            fe=sqrt(1./ivar)*ff*10**(0.8*self.sdss_abfix[wave])

                            mm=22.5-2.5*log10(ff)
                            me=(2.5/log(10))*fe/ff

                        flux[wave][ipoint]=ff
                        ferr[wave][ipoint]=fe
                        mag[wave][ipoint]=mm
                        merr[wave][ipoint]=me

                    ipoint=ipoint+1


        ##ADD THE DATA TO THE DICTIONARY FOR EACH WAVELENGTH
        for wave in self.sdss_waves:
            newdata={}
            newdata['mag']=mag[wave]
            newdata['merr']=merr[wave]
            newdata['flux']=flux[wave]
            newdata['ferr']=ferr[wave]
            newfile[wave]=newdata
        newfile['label']=labels
        newfile['ra']=xpos
        newfile['dec']=ypos
        

        ##AND ADD TO THE MASTER DICTIONARY
        self.alldata[os.path.basename(self.datafile)]=newfile
        ##UPDATE LIST OF LOADED FILES
        self.filelist.append(os.path.basename(self.datafile))
        
        #CLOSE THE WINDOW AND FILE
        self.top.destroy()
        close(self.datafile)

        ##UPDATE MAIN WINDOW - LIST OF WAVELENGTHS AND FILES
        self.update_choices()
        self.add_row()

    #========================================================================
    def sdss_load_preset(self):

        #???UPDATE THIS
        #GET FILE NAME
        datafile=tkFileDialog.askopenfilename()

        if(datafile != ""):
            try:
                var=pickle.load(open(datafile,"r"))
            except:
                message="Not a valic preset file."
                tkMessageBox.showerror("Error",message)
                return

        else:
            return

        #ASSEMBLE VARIABLES

        if 0==0:
            vals=var[0]
            errs=var[1]

            ii=0
            for wave in self.sdss_waves: 
                
                self.sdss_choice[wave].set(vals[ii])
                self.sdss_errchoice[wave].set(errs[ii])
                ii=ii+1
       
        #except:       
        #    message="Not a valid preset file"
        #    tkMessageBox.showerror("Error",message)
        #    return


    #========================================================================
    def sdss_save_preset(self):

        #???UPDATE THIS


        
        vals=[]
        errs=[]

        for wave in self.sdss_waves:
            vals.append(self.sdss_choice[wave].get())
            errs.append(self.sdss_errchoice[wave].get())
            
        var=[vals,errs]

        print "ZZ",vals
        print errs

        datafile=tkFileDialog.asksaveasfilename()

        if(datafile != ""):
            pickle.dump(var,open(datafile,"w"))

            

    #========================================================================
    def sdss_clear_values(self):

        for wave in self.sdss_waves:
            self.sdss_choice[wave].set()
            self.sdss_errchoice[wave].set('None')
            

    #========================================================================
 
    def read_irsa_file(self):
        
        """

        READ FROM AN IRSA/GATOR FILE. THE PROGRAM FIRST PARSES THE CHOSEN FILE TO SELECT COLUMNS THAT 
        ARE POTENTIALLY THE SOURCE NAME, FLUXES, MAGNITUDES OR UNCERTANTIES, AND THEN ASKS THE USER
        TO SELECT THE APPROPRIATE COLUMNS BEFORE READING THEM IN. 
    
        SOURCE NAME = COLUMN WITH A CHARACTER DATA TYPE
        FLUX = UNITS OF Jy, uJy, or mJy
        MAG = UNITS OF mag
        XPOS = UNITS of deg, type=real
        YPOS = UNITS of deg, type=real

        """

        #GET THE FILE NAME

        self.datafile=tkFileDialog.askopenfilename()

        ##IF NO FILE CHOSEN, EXIT WITHOUT DOING ANYTHING
        if(self.datafile == ""):
            return

        self.newdata={}        #DATA FOR A SINGLE FILE
        self.unitlist=[]       #LIST OF UNITS
        self.columnlist=[]     #LIST OF COLUMN HEADERS
        self.columnnum=[]      #INDEX OF POTENTIAL COLUMNS
        self.nulllist=[]       #LIST OF NULL VALUES
        self.namenum=[]        #INDICES TO GO WITH SOURCE NAME OPTIONS
        self.posnum=[]         #INDICES TO GO WITH SOURCE POSITION OPTIONS
        self.namelist=[]       #LIST OF POTENTIAL SOURCE NAME COLUMNS
        self.poslist=[]        #LIST OF POTENTIAL SOURCE POSITION COLUMNS
        self.alllines=[]       #HOLDS INITIAL DATA
        self.npoints=0         #NUMBER OF POINTS
        inline=0               #COUNTER TO KEEP TRACK OF WHERE IN FILE

        #if (0==0):
        try:

        	##LISTS TO HOLD INFORMATION
        	
        	
            #GO THROUGH THE LINES
            for line in open(self.datafile):
        	
                #COMMENT LINE - IGNORE
                if(line[0]=="\\"):
                    pass
        	        
                    #HEADER LINES GET READ IN AND SPLIT USING "|" AS A SEPARATOR
                    
                    #FIRST HEADER LINE - NAMES OF COLUMN
                elif((line[0]=="|") & (inline==0)):
                    columns=line.split("|")
                    inline=1
                    #SECOND HEADER LINE - VARIABLE TYPE
                elif((line[0]=="|") & (inline==1)):
        	
                    datatype=line.split("|")
                    inline=2
                    #THIRD HEADER LINE - UNITS
                elif((line[0]=="|") & (inline==2)):
                    units=line.split("|")
                    inline=3
                    #FOURTH HEADER LINE - NULL VALUE
        	
                elif((line[0]=="|") & (inline==3)):
        	
                    inline=4
                    nulls=line.split("|")
        	
                elif(inline==4):
                    if(len(columns)==0):
                        ##ERROR MESSAGE - no valid columns
                        tkMessageBox.showwarning("No Valid Columns in File")
                        return
        	
                    for i in range(len(columns)):
        	
                        #LOOK FOR FLUX/MAG UNITS, BUT EXCLUDE SURFACE BRIGHTNESS
                        if(("jy" in units[i].lower()) | ("mag" in units[i].lower()) and ("jy/s" not in units[i].lower())):
                            self.unitlist.append(units[i].strip())
                            self.columnlist.append(columns[i].strip())
                            self.columnnum.append(i)
                            self.nulllist.append(nulls[i].strip())
        	          
        	           
        	
                            #LOOK FOR CHARACTER STRINGS (NO UNITS, DATA-TYPE=char)
                        if((units[i].strip()=="") & (columns[i].strip() != "") & (datatype[i].strip().lower()=="char")):
                            self.namelist.append(columns[i].strip())
                            self.namenum.append(i)
        	
                            #LOOK FOR POSITION HEADERS (UNITS OF DEG, BUT NOT INT [WHICH IS USUALLY POSITION ANGLE OR 
                            #SOMETHING LIKE THAT])
                        if(("deg" in units[i].lower()) & ("int" not in datatype[i].lower()) & (('ra' in columns[i].lower()) | ('dec' in columns[i].lower()))):
                            self.poslist.append(columns[i].strip())
                            self.posnum.append(i)
        	
        	            
                        inline=5 
                    if(self.unitlist==[]):
                        tkMessageBox.showwarning("No Valid Columns in File")
                    if(self.namelist==[]):
                        tkMessageBox.showwarning("No Column Headers")
        	
                    self.alllines.append(line)
                    self.npoints=self.npoints+1
        	
                    #CATALOGUE LINE - READ IN LINE TO LIST
                else:
                    self.alllines.append(line)
        	
                    self.npoints=self.npoints+1
        	
            if(len(columns)==0):
                ##ERROR MESSAGE - no valid columns
                tkMessageBox.showwarning("No Valid Columns in File")
                return
        	
            ##FIGURE OUT THE FIELD LENGTH OF EACH ITEM - USE THIS INSTEAD OF SPLIT TO ACCOUNT FOR SPACES IN FIELDS
            ##IRSA CATALOGUES HAVE FIXED WIDTH LINES - USE THE COLUMN HEADERS TO CALCULATE THEM
            self.entrylist=[]
            tot=0
            for i in range(len(columns)):
        	
                #I=0 IS EXCLUDED BECASUE THE HEADER LINES START WITH A SEPARATOR
                if(i > 0):
                    #GET THE INDEX OF THE START OF EACH COLUMN
                    self.entrylist.append(tot)
                    tot=tot+len(columns[i])+1
        	
            self.top=Toplevel(self) 

            self.top.title('Select Columns')

            #VARIABLES FOR THE USER SELECTION
            self.choice1=[]             #THE LIST OF TICK BOXES TO SELECT FLUX COLUMNS
            self.choice2=[]             #VAR FOR DROP DOWN MENU CHOICE OF UNCERTAINTIES
            self.whichlab=StringVar()   #VAR FOR DROP DOWN MENU CHOICE OF PS NAME
            self.whichxpos=StringVar()   #VAR FOR DROP DOWN MENU CHOICE OF X POSITION COLUMN
            self.whichypos=StringVar()   #VAR FOR DROP DOWN MENU CHOICE OF Y POSITION COLUMN
            
            #SETUP THE WINDOW BASED ON COLUMNS. ATTACH A SCROLLBAR FOR LONG LISTS
        	
            #FIRST SET UP THE FRAME AND THE SCROLLBAR, AND ATTACH TO A CANVAS
            self.window=Frame(self.top)
            self.irsa_canvaschoice=Canvas(self.window)
            self.box=Frame(self.irsa_canvaschoice)
            self.scroll=Scrollbar(self.window,orient=VERTICAL,command=self.irsa_canvaschoice.yview)
            self.irsa_canvaschoice.configure(yscrollcommand=self.scroll.set)
            self.scroll.pack(side="right",fill="y")
            self.irsa_canvaschoice.create_window((0,0),window=self.box,anchor="nw",tags="self.filelist")
            self.box.bind("<Configure>",self.irsa_OnFrameConfigure)
            self.irsa_canvaschoice.pack(side="left",fill="both")
        	
            #TOP LINE OF CHOICES - PS NAME, EXIT BUTTON
            self.greep=Frame(self.box)
        	
            lab0=Button(self.greep,text='Load Values and Close',command=self.irsa_readquit).grid(row=0,column=0)
            lab1=Button(self.greep,text='Load Preset',command=self.irsa_load_preset).grid(row=0,column=1)
            lab1=Button(self.greep,text='Save Preset',command=self.irsa_save_preset).grid(row=0,column=2)
            lab1=Button(self.greep,text='Clear',command=self.irsa_clear_values).grid(row=0,column=3)
            lab1=Button(self.greep,text='Cancel',command=self.top.destroy).grid(row=0,column=4)
            lab2=Label(self.greep,text="Label: ",).grid(row=1,column=0)
            lab2=OptionMenu(self.greep,self.whichlab,*self.namelist)
            lab2.config(width=20)
            lab2.grid(row=1,column=1)
            self.whichlab.set(self.namelist[0])
        	
            lab2=Label(self.greep,text="X POS: ",).grid(row=2,column=0)
            lab2=OptionMenu(self.greep,self.whichxpos,*self.poslist)
            lab2.config(width=20)
            lab2.grid(row=2,column=1)
            lab2=Label(self.greep,text="Y POS: ",)
            lab2.config(width=20)
            lab2.grid(row=2,column=2)
            lab2=OptionMenu(self.greep,self.whichypos,*self.poslist)
            lab2.config(width=12)
            lab2.grid(row=2,column=3)
            self.whichxpos.set(self.poslist[0])
            self.whichypos.set(self.poslist[1])
        	
            
            #LABELS FOR COLUMNS
            lab1=Label(self.greep,text="Flux",width=20).grid(row=3,column=0)
            lab2=Label(self.greep,text="Units").grid(row=3,column=1)
            lab2=Label(self.greep,text="Uncertainty").grid(row=3,column=2)
        	
            #NOW CYCLE THROUGH LIST. ONE ITEM FOR EACH POTENTIAL FLUX COLUMN, DROP DOWN MENU CONTAINS ALL THE 
            #POTENTIAL VALUES. 
        	
            for i in range(len(self.columnlist)):
                self.choice1.append(IntVar())
                self.choice2.append(StringVar())
                choice1=Checkbutton(self.greep,variable=self.choice1[i],text=self.columnlist[i],width=20).grid(row=i+3,column=0)
                choice3=Label(self.greep,text=self.unitlist[i]).grid(row=i+3,column=1)
                choice2=OptionMenu(self.greep,self.choice2[i],*self.columnlist)
                choice2.config(width=20)
                choice2.grid(row=i+3,column=2)
                self.choice2[i].set('None')
                self.choice1[i].set(0)
            self.greep.grid(row=0,column=0)
            self.window.grid(row=0,column=0,sticky=NW)
        	
            #CONFIGURE THE WINDOW SIZE
            self.window.configure(height=400)
            self.box.configure(height=400)
        	
            #THE WINDOW CALLS IRSA_READQUIT, WHICH LOADS THE COLUMNS AND EXITS
        except:
            message="I think you've got the wrong file..."
            tkMessageBox.showerror("Error",message)
            return

    #========================================================================

    def irsa_readquit(self):

        """
    
        ROUTINE READ CHOSEN COLUMNS FROM AN GATOR/IRSA FILES, AS SELECTED IN THE PREVIOUS ROUTINE

        """
  
        newfile={}   #DICTIONARY TO HOLD VALUES
        nyes=0

        ##FIGURE OUT NUMBER OF SELECTED FLUX COLUMNS TO MAKE THE ARRAYS

        #CYCLE THROUGH THE LINES
        for i in range(len(self.columnlist)):
            if(self.choice1[i].get()==1):
                nyes=nyes+1

        ##MAKE ARRAYS FOR FLUX, MAGNITUDE AND ERRORS
        flux=zeros((self.npoints,nyes))
        ferr=zeros((self.npoints,nyes))
        mag=zeros((self.npoints,nyes))
        merr=zeros((self.npoints,nyes))
        labels=[]
        xpos=[]
        ypos=[]
        vals=[]

        #GET THE INDEX FOR THE SOURCE NAME COLUMN
        ind1=self.namelist.index(self.whichlab.get())
        ind_x=self.poslist.index(self.whichxpos.get())
        ind_y=self.poslist.index(self.whichypos.get())

        
        self.xpos_name=self.whichxpos.get()
        self.ypos_name=self.whichypos.get()

        #INITIALIZE VARIABLES
        self.uncertnum=[]
        self.fluxlist=[]
        self.uncertlist=[]
        self.fluxnum=[]
        self.nullval=[]
        self.uncertnull=[]
        ##NOW GO THROUGH COLUMNS PICK OUT THE SELECTED ONES
        nselect=0
        for i in range(len(self.columnlist)):
            if(self.choice1[i].get()==1):
                nselect=nselect+1
                ##ADD TO THE MASTER WAVELENGTH LIST, FLUX LIST, AND GET THE INDEX
                self.wavelist.append(self.irsaval[self.columnlist[i]][0])
                self.fluxlist.append(self.columnlist[i])
                self.fluxnum.append(i)
                self.nullval.append(self.nulllist[i])
                #GET THE INFORMATION FOR UNCERTAINTIES
                if(self.choice2[i].get() == "None"):
                    self.uncertnum.append("None")
                else:
                    self.uncertlist.append(self.choice2[i].get())
                    ind=self.columnlist.index(self.choice2[i].get())
                    self.uncertnum.append(ind)
                    self.uncertnull.append(self.nulllist[ind])
        #FOR EACH LINE

        print self.wavelist
        print self.fluxlist
        print self.fluxnum
        print self.nullval
        print self.uncertlist
        print self.uncertnum
        print self.uncertnull

        print "A",self.npoints
        for j in range(self.npoints):

            ##SPLIT THE LINE, USING THE COLUMN WIDTHS AS CALCULATED, APPEND TO A LIST
            vals=[]

            strline=self.alllines[j]
            for k in range(len(self.entrylist)-1):
                vals.append(strline[self.entrylist[k]:self.entrylist[k+1]])
                print 'AA'+strline[self.entrylist[k]:self.entrylist[k+1]]+"AA"
                #print self.nulllist[i]

            #print "CC",self.namenum[ind1]-1,vals[self.namenum[ind1]-1]
            labels.append(vals[self.namenum[ind1]-1])

            xpos.append(float(vals[self.posnum[ind_x]-1]))
            ypos.append(float(vals[self.posnum[ind_y]-1]))

            #NOW FOR THE COLUMNS


            for i in range(nselect):

                
                ##NOTE THAT THERE IS A +1 FOR THE INDEX IN THE FLUX COLUMN, AS THE 
                ##HEADER COLUMNS START WITH A SEPARATOR, OFFSETING THE COLUMNS
 
                ##FLUX CASE 

                if('jy' in self.unitlist[self.fluxnum[i]].lower()):

                    #GET CONVERSION FACTOR
                    if('jy' in self.unitlist[self.fluxnum[i]].lower()):
                        factor=1.
                    if('mjy' in self.unitlist[self.fluxnum[i]].lower()):
                        factor=1e-3
                    if('uJy' in self.unitlist[self.fluxnum[i]].lower()):
                        factor=1e-6
                        
                    ##CHECK FOR NULL VALUE
                    if ((vals[self.columnnum[self.fluxnum[i]]-1].strip() == self.nullval[i])):
                        flux[j,i]=numpy.nan
                        ferr[j,i]=numpy.nan
                        mag[j,i]=numpy.nan
                        merr[j,i]=numpy.nan


                    else:
                        #CHECK FOR NON VALID ENTRIES
                        try:
                            tt=float(vals[self.columnnum[self.fluxnum[i]]-1])
                        except:
                            ##ERROR NON NUMBER LINE NAME???
                            tkMessageBox.showwarning("Non Number Character in File")
                            return
                    
                        ##PHYSICALLY IMPOSSIBLE CASE OF FLUX < 0
                        if(float(vals[self.columnnum[self.fluxnum[i]]-1]) < 0):
                            flux[j,i]=numpy.nan
                            ferr[j,i]=numpy.nan
                            mag[j,i]=numpy.nan
                            merr[j,i]=numpy.nan

                        ##NOT A NULL
                        else:

                            flux[j,i]=float(vals[self.columnnum[self.fluxnum[i]]-1])*factor
                            mag[j,i]=-2.5*log10(flux[j,i]/self.irsaval[self.fluxlist[i]][2])
                            #CASE FOR NO UNCERTAINTIES
                            if(self.uncertnum[i]=="None"):
                                ferr[j,i]=0
                                merr[j,i]=0
                                #INCLUDED UNCERTAINTIES
                            else:

                                ##NULL VAL ERRORS
                                if(vals[self.columnnum[self.fluxnum[i]]-1] == self.uncertnull[i]):
                                    ferr[j,i]=0
                                    merr[j,i]=0
                                elif(float(vals[self.columnnum[self.fluxnum[i]]-1]) < 0):
                                    ferr[j,i]=0
                                    merr[j,i]=0
                                else:

                                    ferr[j,i]=float(vals[self.columnnum[self.uncertnum[i]]-1])*factor
                                    merr[j,i]=(2.5/log(10))*ferr[j,i]/flux[j,i]
                    ##MAG CASE
                elif('mag' in self.unitlist[i].lower()):

                    
                    #CHECK FOR NULL VALUE IN MAG
                    if (vals[self.columnnum[self.fluxnum[i]]-1].strip() == self.nullval[i]):
                        flux[j,i]=numpy.nan
                        ferr[j,i]=numpy.nan
                        mag[j,i]=numpy.nan
                        merr[j,i]=numpy.nan
                    else:

                        try:
                            mag[j,i]=float(vals[self.columnnum[self.fluxnum[i]]-1])
                            flux[j,i]=self.irsaval[self.fluxlist[i]][2]*10**(-0.4*mag[j,i])
                        except:
                            ##ERROR MESSAGE INVALID LINE #???
                            tkMessageBox.showwarning("Non Number Character in File")
                            return

                        #CASE FOR NO UNCERTAINTIES

                        if(self.uncertnum[i]=="None"):
                            ferr[j,i]=0
                            merr[j,i]=0
                        elif(vals[self.columnnum[self.uncertnum[i]]-1].strip() == self.uncertnull[i].strip()):
                            ferr[j,i]=0
                            merr[j,i]=0
                        elif(float(vals[self.columnnum[self.uncertnum[i]]-1]) < 0):
                            ferr[j,i]=0
                            merr[j,i]=0
                        else:
                            if(0==0):
                            #try:
                                merr[j,i]=float(vals[self.columnnum[self.uncertnum[i]]-1])
                                ferr[j,i]=self.irsaval[self.fluxlist[i]][2]*10**(-0.4*float(vals[self.columnnum[self.uncertnum[i]]-1]))

                                ##INCLUDED UNCERTAINTIES, AS BEFORE
                    
                            #except:
                            #    ##ERROR _ INVALID UNCERT LINE???
                            #    print "HERE4",vals[self.uncertnum[i]]
                            #    print ferr[j,i]
                            #    print flux[j,i]
                            #
                            #    return

        if(len(self.fluxlist)==0):
            tkMessageBox.showwarning("No Valid Fluxes Found")
            ##ERRROR NFLUX???
            return

        #NOW LOAD THE COLUMNS INTO THE DATA DICTIONARY FOR THAT FILE
        for i in range(len(self.fluxlist)):

            newdata={}
            newdata['mag']=mag[:,i]
            newdata['flux']=flux[:,i]
            newdata['merr']=merr[:,i]
            newdata['ferr']=ferr[:,i]
            newfile[self.irsaval[self.fluxlist[i]][0]]=newdata     
        newfile['label']=labels
        newfile['ra']=xpos
        newfile['dec']=ypos

        #AND ADD IT TO THE MASTER DICTIONARY - THE FILE NAME AS THE TAG
        self.alldata[os.path.basename(self.datafile)]=newfile
     
        #UPDATE THE MASTER WAVELENGTH LIST, SORT AND REMOVE DUPLICATES
        self.wavelist=list(set(self.wavelist))
        sortwave=[]
        for wave in self.wavelist:
            sortwave.append(self.waveband[wave][1])

        self.wavelist=list(zip(*sorted(zip(sortwave,self.wavelist)))[1])
     
        #UPDATE THE LIST OF LOADED FILES
        self.filelist.append(os.path.basename(self.datafile))

        #CLOSE THE WINDOW AND FILE
        self.top.destroy()
        close(self.datafile)

        #UPDATE MAIN WINDOW - WAVELENGHTS AND FILE LIST
        self.add_row()
        self.update_choices()

    #========================================================================
    ##ROUTINES FOR SAVING/LOADING/CLEARING PRESETS FOR IRSA FILES

    def irsa_save_preset(self):
        
        """
        SAVE THE LIST OF CHOSEN COLUMNS/UNCERTAINTIES 

        """

        ##SET UP VARIABLES
        chosen=[]
        uncert=[]

        #GET CHOCIE OF LABEL/X/Y POSITIONS
        label=self.whichlab.get()
        xpos=self.whichxpos.get()
        ypos=self.whichypos.get()

        #CCYCLE THROUGH LIST AND PULL OUT SELECTED COLUMNS
        for i in range(len(self.columnlist)):
            if(self.choice1[i].get()==1):
                chosen.append(self.columnlist[i])
                uncert.append(self.choice2[i].get())

        #PUT IN A LIST AND SAVE IN A USER SELECTED FILE
        var=[chosen,uncert,label,xpos,ypos]

        datafile=tkFileDialog.asksaveasfilename()

        if(datafile != ""):
            pickle.dump(var,open(datafile,"w"))
   
        
    #========================================================================

    def irsa_load_preset(self):

        """

        ROUTINE TO LOAD A PRESET SELECTION OF CHOSEN COLUMNS FOR AN IRSA FILE

        """

        #GET FILE NAME
        datafile=tkFileDialog.askopenfilename()

        if(datafile != ""):
            try:
                var=pickle.load(open(datafile,"r"))
            except:
                message="Not a valic preset file."
                tkMessageBox.showerror("Error",message)
                return

        else:
            return

        #ASSEMBLE VARIABLES

        try:
            chosen=var[0]
            uncert=var[1]
            label=var[2]
            xpos=var[3]
            ypos=var[4]

            #SET THE LABEL/XPOS/YPOS
            self.whichlab.set(label)
            self.whichxpos.set(xpos)
            self.whichypos.set(ypos)

            #CYCLE THROUGH THE FLUX/ERRORS AND SET LABELS

            for i in range(len(self.columnlist)):
                for j in range(len(chosen)):
                    if(self.columnlist[i] == chosen[j]):
                        self.choice1[i].set(1)
                        self.choice2[i].set(uncert[j])


        except:
            message="Not a valid preset file"
            tkMessageBox.showerror("Error",message)
            return

    #========================================================================

    def irsa_clear_values(self):

        """
        CLEAR THE SELECTIONS IN THE IRSA MENU

        """

        for i in range(len(self.columnlist)):
            self.choice1[i].set(0)
            self.choice2[i].set("None")
            self.whichlab.set(self.namelist[0])

    #========================================================================

    def read_text_file(self):

        """
      
        ROUTINE TO READ A GENERAL TEXT FILE. THE FORMAT OF A GENERAL TEXT FILE
        IS FIRST COLUMN ???

        """

        newfile={}
        
        ##USER QUERY FOR FILE
        datafile=tkFileDialog.askopenfilename()
        
        ##IF NO FILE CHOSEN, EXIT WITHOUT DOING ANYTHING
        if(datafile == ""):
            return

        infile=0     ##FLAG FOR WHICH LINE OF THE FILE
        npoint=0     ##NUMBER OF POINTS
        localwave=[] ##VARIABLE WITH THE WAVELENGHTS FOR THIS FILE
        unitlist=[]  ##UNITS TO GO WITH LOCALWAVE, FOR CONVERSIONS

        #GET THE LENGTH OF THE FILE, CHECK FOR VALID INPUT - ADD ERROR TRAPPING??

        #FOR EACH LINE IN THE FILE
        for line in open(datafile):

            ##FIRST LINE HAS WAVEBANDS
            if(infile==0):
                names=line.split()

                ##ADD TO LIST OF POSSIBLE WAVELENGTHS. THE FIRST FOR ALL FILES,
                ##THE SECOND FOR THIS FILE ONLY
                for item in names:
                    #CHECK FOR VALID FILTER NAMES
                    try:
                        self.wavelist.append(self.waveval[item][0])
                        localwave.append(item)
                    except:
                        message="First line of file does not contain valid filters."
                        tkMessageBox.showerror("Error",message)
                        return

                ##GET NUMBER OF FLUXES
                nflux=len(names)
                infile=1

                ##SECOND LINE HAS UNITS, HANDLES THE SAME WAS AS LOCALWAVE
            elif(infile==1):
                units=line.split()
                for item in units:
                    ##CHECK FOR VALID UNITS
                    if(item.lower().strip() in self.accepted_units): 
                        unitlist.append(item)
                    else:
                        message="Second line of file does not contain valid units."
                        tkMessageBox.showerror("Error",message)
                        return

                infile=2

                ##OTHERWISE ITS A FLUX

            #CHECK FOR NUMBER OF ENTRIES
            elif(infile==2):
                if((len(line.split()) == 2*nflux+3)):
                    npoint=npoint+1
                    include_errors=1
                elif ((len(line.split()) == nflux+3)):
                    npoint=npoint+1
                    include_errors=0
                else:
                    message="Incorrect number of fluxes/errors on data line "+str(point+1)
                    tkMessageBox.showerror("Error",message)
                    return

                infile=3

            elif(infile > 2):
                if((len(line.split()) == 2*nflux+3) & (include_errors==1)):
                    npoint=npoint+1
                elif((len(line.split()) == nflux+3) & (include_errors==0)):
                    npoint=npoint+1
                else:
                    message="Incorrect number of fluxes/errors on data line "+str(point+1)
                    tkMessageBox.showerror("Error",message)
                    return

        ##CLOSE THE FILE

        close(datafile)

        print localwave
        print unitlist

        ##NO WAVELENGTHS
        if((localwave==[]) | (unitlist==[])):
            message="No valid filters and/or units."
            tkMessageBox.showerror("Error",message)
            return
        
        ##REMOVE DUPLICATE WAVELENGTHS FROM MASTER LIST AND SORT BY WAVELENGTH

        self.wavelist=list(set(self.wavelist))
        sortwave=[]
        
        for wave in self.wavelist:
            sortwave.append(self.waveband[wave][1])

        self.wavelist=list(zip(*sorted(zip(sortwave,self.wavelist)))[1])

        #SET UP VARIABLES - NUMPY ARRAY FOR MAGNITUDES AND THEIR ERRORS, FLUXES AND THERE ERRORS, 
        #A LIST FOR UPPER/LOWER LIMIT FLAG AND LABELS OF POINTS 
        mags=zeros((npoint,nflux))
        merr=zeros((npoint,nflux))
        flux=zeros((npoint,nflux))
        ferr=zeros((npoint,nflux))

        print "npoint,nflux,errors=",npoint,nflux,include_errors
        labels=[]
        lim=[]
        endmessage=""

        #READ THE DATA INTO THE ARRAY

        xpos=[]
        ypos=[]
        ##COUNTERS AS BEFORE
        point=0
        infile=0
        for line in open(datafile):

            ##IGNORE FIRST TWO LINES
            if(infile<2):
                infile+=1
            else:
                entries=line.split()
                labels.append(entries[0])

                #CHECK FOR VALID RA AND DEC, ERROR AND EXIT IF THERE IS A PROBLEM
                try:

                    ra=float(entries[1])
                    dec=float(entries[2])
                    xpos.append(ra)
                    ypos.append(dec)

                except:
                    message="Incorrect RA or Dec in data line "+str(point+1)
                    tkMessageBox.showerror("Error",message)
                    return

                if((ra < 0) | (ra > 360) | (dec < -180) | (dec > 180)):
                    message="RA or Dec out of range on data line "+str(point+1)
                    tkMessageBox.showerror("Error",message)
                    return

                if(include_errors==1):

                    for i in range(0,nflux*2,2):

                
                        ##FIGURE OUT UNITS AND CONVERT TO Jy
                        ##?? ADD MORE UNITS - Fnu, Flam
                        unit=unitlist[i/2]
                        ##is it flux units?
                        if(unit.lower() != 'mag'):
               
                            ##FIRST GET THE CONVERSTION FACTOR TO JY, WHICH IS THE UNIT FOR THE ZERO POINTS
                            if(unit=="Jy"):
                                conv=1.
                            if(unit=="mJy"):
                                conv=1e-3
                            if(unit=="uJy"):
                                conv=1e-6
                            if(unit.lower=="w/m2/hz"):
                                conv=1e-23
                            if(unit.lower=="erg/cm2/hz"):
                                conv=1e-26
                

                            ##CALCULATE MAGNITUDE FROM WAVELENGTH
                            ##TEMP VARS FOR FLUX AND FLUX ERROR

                            #CHECK FOR INVALID RESULT, CONVERT TO FLOAT, AND APPLY CONVERSTION FACTOR
                            try:
                                ff=float(entries[i+3])*conv
                                fe=float(entries[i+4])*conv
                            except:
                                message="Incorrect flux in data line "+str(point+1)
                                tkMessageBox.showerror("Error",message)
                                return

                            if (ff < 0):
                                endmessage="Found negative fluxes or errors; these will be ignored."
                                ff=nan

                            if (fe < 0):
                                endmessage="Found negative fluxes or errors; these will be ignored."
                                fe=0

                            #NO VALID FLUX CASE (NAN)
                            if(ff==nan):
                                mags[point,i/2]=nan
                                merr[point,i/2]=nan
                                flux[point,i/2]=nan
                                ferr[point,i/2]=nan
 
                            else:

                                ##AND CALCULATE THE OTHER VALUES
                                mags[point,i/2]=-2.5*log10(ff/self.waveval[localwave[i/2]][2])
                                flux[point,i/2]=ff
                                ferr[point,i/2]=fe

                            ##KEEP AN ERROR OF ZERO, BUT DO A CONVERSION FOR A NON ZERO ERROR. 
                            if(fe=='0'):
                                merr[point,i/2]=0
                            else:
                                merr[point,i/2]=(2.5/log(10))*ferr[j,i]/f[j,i]
                                
                        ##NOW DO THE REVERSE CASE FOR MAGNITUDES
                        if(unit.lower() == 'mag'):

                            #CHECK FOR VALIDITY
                            try:
                                mm=float(entries[i+3])
                                me=float(entries[i+4])
                            except:
                                message="Incorrect flux in data line "+str(point+1)
                                tkMessageBox.showerror("Error",message)
                                return

                            if (mm==nan):
                                mags[point,i/2]=nan
                                merr[point,i/2]=nan
                                flux[point,i/2]=nan
                                ferr[point,i/2]=nan

                            else:
          
                                ##AND CALCULATE OTHER VALUES
                                flux[point,i/2]=self.waveval[localwave[i/2]][2]*10**(-mm/2.5)
                                mags[point,i/2]=mm
                                merr[point,i/2]=me
          
                                ##KEEP AN ERROR OF ZERO, BUT DO A CONVERSION FOR A NON ZERO ERROR. 
                                if(me=='0'):
                                    ferr[point,i/2]=0
                                else:
                                    ferr[point,i/2]=float(me)*float(flux[point,i/2])/(2.5/log(10))

                    ##UPDATE THE CURRENT POINT
                    point=point+1

                if(include_errors==0):

                    for i in range(0,nflux):

                
                        ##FIGURE OUT UNITS AND CONVERT TO Jy
                        ##?? ADD MORE UNITS - Fnu, Flam
                        unit=unitlist[i]
                        ##is it flux units?
                        if(unit.lower() != 'mag'):
               
                            ##FIRST GET THE CONVERSTION FACTOR TO JY, WHICH IS THE UNIT FOR THE ZERO POINTS
                            if(unit=="Jy"):
                                conv=1.
                            if(unit=="mJy"):
                                conv=1e-3
                            if(unit=="uJy"):
                                conv=1e-6
                            if(unit.lower=="w/m2/hz"):
                                conv=1e-23
                            if(unit.lower=="erg/cm2/hz"):
                                conv=1e-26

                            ##CALCULATE MAGNITUDE FROM WAVELENGTH
                            ##TEMP VARS FOR FLUX AND FLUX ERROR

                            #CHECK FOR INVALID RESULT, CONVERT TO FLOAT, AND APPLY CONVERSTION FACTOR
                            try:
                                ff=float(entries[i+3])*conv
                                fe=float(entries[i+4])*conv
                            except:
                                message="Incorrect flux in data line "+str(point+1)
                                tkMessageBox.showerror("Error",message)
                                return

                            #NO VALID FLUX CASE (NAN)
                            if(ff==nan):
                                mags[point,i]=nan
                                merr[point,i]=nan
                                flux[point,i]=nan
                                ferr[point,i]=nan
 
                            else:

                                ##AND CALCULATE THE OTHER VALUES
                                mags[point,i]=-2.5*log10(ff/self.waveval[localwave[i]][2])
                                flux[point,i]=ff
                                ferr[point,i]=fe

                            ##KEEP AN ERROR OF ZERO, BUT DO A CONVERSION FOR A NON ZERO ERROR. 
                            if(fe=='0'):
                                merr[point,i]=0
                            else:
                                merr[point,i]=(2.5/log(10))*ferr[j,i]/f[j,i]
                                
                        ##NOW DO THE REVERSE CASE FOR MAGNITUDES
                        if(unit.lower() == 'mag'):

                            #CHECK FOR VALIDITY
                            try:
                                mm=float(entries[i+3])
                                me=float(entries[i+4])
                            except:
                                message="Incorrect flux in data line "+str(point+1)
                                tkMessageBox.showerror("Error",message)
                                return

                            if (mm==nan):
                                mags[point,i]=nan
                                merr[point,i]=nan
                                flux[point,i]=nan
                                ferr[point,i]=nan

                            else:
          
                                ##AND CALCULATE OTHER VALUES
                                flux[point,i]=self.waveval[localwave[i]][2]*10**(-mm/2.5)
                                mags[point,i]=mm
                                merr[point,i]=me
          
                                ##KEEP AN ERROR OF ZERO, BUT DO A CONVERSION FOR A NON ZERO ERROR. 
                                if(mm=='0'):
                                    ferr[point,i]=0
                                else:
                                    ferr[point,i]=float(me)*float(flux[point,i])/(2.5/log(10))

                    ##UPDATE THE CURRENT POINT
                    point=point+1
 

        #ADD THE DATA TO THE DICTIONARY FOR EACH WAVELENGTH
        for i in range(nflux):
            newdata={}
            newdata['mag']=mags[:,i]
            newdata['merr']=merr[:,i]
            newdata['flux']=flux[:,i]
            newdata['ferr']=ferr[:,i]
            newfile[self.waveval[names[i]][0]]=newdata
        newfile['label']=labels
        newfile['ra']=xpos
        newfile['dec']=ypos

        #SHOW ANY NON CRASHING WARNINGS

        if (endmessage != ""):
            tkMessageBox.showerror("Warning",message)

        #AND ADD TO THE MASTER DICTIONARY
        self.alldata[os.path.basename(datafile)]=newfile
        #UPDATE LIST OF LOADED FILES
        self.filelist.append(os.path.basename(datafile))
            
        #UPDATE MAIN WINDOW - LIST OF WAVELENGTHS AND FILES
        self.update_choices()
        self.add_row()
    #========================================================================

    ##ROUTINES TO CONFIGURE SCROLLBAR FOR IRSA/SDSS MENUS

    def sdss_OnFrameConfigure(self,event):

        """

        CONFIGURE THE CANVAS WITH THE SCROLLBAR. SET THE SCROLL REGION, AND EXPAND
        THE WIDTH TO FIT THE CONTENTS.

        """
        self.sdss_canvaschoice.configure(scrollregion=self.sdss_canvaschoice.bbox("all"),)
        self.sdss_canvaschoice.config(width=event.width,height=400)

    #========================================================================

    def irsa_OnFrameConfigure(self,event):

        """

        CONFIGURE THE CANVAS WITH THE SCROLLBAR. SET THE SCROLL REGION, AND EXPAND
        THE WIDTH TO FIT THE CONTENTS.

        """
        self.irsa_canvaschoice.configure(scrollregion=self.irsa_canvaschoice.bbox("all"),)
        self.irsa_canvaschoice.config(width=event.width,height=400)

    #========================================================================
    
    def read_overplot(self):

        """
      
        ROUTINE TO READ A FILE WITH  OVERPLOT INFORMATION. THE FORMAT IS ???

        """

        newfile={}
        
        ##USER QUERY FOR FILE
        datafile=tkFileDialog.askopenfilename()
        
        ##IF NO FILE CHOSEN, EXIT WITHOUT DOING ANYTHING
        if(datafile == ""):
            return

        infile=0     ##FLAG FOR WHICH LINE OF THE FILE
        npoint=0     ##NUMBER OF POINTS
        localwave=[] ##VARIABLE WITH THE WAVELENGHTS FOR THIS FILE
        unitlist=[]  ##UNITS TO GO WITH LOCALWAVE, FOR CONVERSIONS
        endmessage=""

        #GET THE LENGTH OF THE FILE, CHECK FOR VALID INPUT - ADD ERROR TRAPPING??

        #FOR EACH LINE IN THE FILE
        for line in open(datafile):

            ##FIRST LINE HAS WAVEBANDS
            if(infile==0):
                names=line.split()

                ##ADD TO LIST OF POSSIBLE WAVELENGTHS. THE FIRST FOR ALL FILES,
                ##THE SECOND FOR THIS FILE ONLY
                for item in names:
                    try:
                        aa=self.waveval[item][0]
                        localwave.append(item)
                    except:
                        message="First line of file does not contain valid filters."
                        tkMessageBox.showerror("Error",message)
                        return

                ##GET NUMBER OF FLUXES
                nflux=len(names)
                infile=1

                ##SECOND LINE HAS UNITS, HANDLES THE SAME WAS AS LOCALWAVE
            elif(infile==1):
                units=line.split()
                for item in units:
                    if(item.lower().strip() in self.accepted_units): 
                        unitlist.append(item)
                    else:
                        message="Second line of file does not contain valid units."
                        tkMessageBox.showerror("Error",message)
                        return

                infile=2

                ##OTHERWISE ITS A FLUX
            elif(infile>1):
                if(len(line.split()) == nflux):
                    npoint=npoint+1
                else:
                    message="Incorrect number of fluxes/errors on data line "+str(npoint+1)
                    tkMessageBox.showerror("Error",message)
                    return

        ##CLOSE THE FILE

        close(datafile)

                
        #SET UP VARIABLES - NUMPY ARRAY FOR MAGNITUDES AND THEIR ERRORS, FLUXES AND THERE ERRORS, 
        #A LIST FOR UPPER/LOWER LIMIT FLAG AND LABELS OF POINTS 
        mags=zeros((npoint,nflux))
        flux=zeros((npoint,nflux))

        lim=[]

        #READ THE DATA INTO THE ARRAY

        ##COUNTERS AS BEFORE
        point=0
        infile=0
        for line in open(datafile):

            ##IGNORE FIRST TWO LINES
            if(infile<2):
                infile+=1
            else:    
                entries=line.split()
                for i in range(0,nflux):
                
                    ##FIGURE OUT UNITS AND CONVERT TO Jy
                    ##?? ADD MORE UNITS - Fnu, Flam
                    unit=unitlist[i]
                    ##is it flux units?
                    if(unit.lower() != 'mag'):
               
                        ##FIRST GET THE CONVERSTION FACTOR TO JY, WHICH IS THE UNIT FOR THE ZERO POINTS
                        if(unit=="Jy"):
                            conv=1.
                        if(unit=="mJy"):
                            conv=1e-3
                        if(unit=="uJy"):
                            conv=1e-6
                        if(unit.lower=="w/m2/hz"):
                            conv=1e-23
                        if(unit.lower=="erg/cm2/hz"):
                            conv=1e-26
 

                            ##CALCULATE MAGNITUDE FROM WAVELENGTH
                            ##TEMP VARS FOR FLUX AND FLUX ERROR

                            try:
                                ff=float(entries[i])*conv
                            except:
                                message="Incorrect flux in data line "+str(npoint+1)
                                tkMessageBox.showerror("Error",message)
                                return

                            if (ff < 0):
                                endmessage="Found negative fluxes or errors; these will be ignored."
                                ff=nan

                            if(ff==nan):
                                mags[point,i]=nan
                                flux[point,i]=nan
                            else:
                                mags[point,i]=-2.5*log10(ff/self.waveval[localwave[i]][2])
                                flux[point,i]=ff
                                
                    ##NOW DO THE REVERSE CASE FOR MAGNITUDES
                    if(unit.lower() == 'mag'):

                        try:
                            mm=float(entries[i])
                        except:
                            message="Incorrect flux in data line "+str(point+1)
                            tkMessageBox.showerror("Error",message)
                            return

                        if(mm==nan):
                            flux[point,i]=nan
                            mags[point,i]=nan
                        else:
                            ##AND CALCULATE
                            flux[point,i]=self.waveval[localwave[i]][2]*10**(-mm/2.5)
                            mags[point,i]=float(mm)

                ##UPDATE THE CURRENT POINT
                point=point+1
                    
        #ADD THE DATA TO THE DICTIONARY FOR EACH WAVELENGTH
        for i in range(nflux):
            newdata={}
            newdata['mag']=mags[:,i]
            newdata['flux']=flux[:,i]
            newfile[self.waveval[names[i]][0]]=newdata

        if (endmessage != ""):
            tkMessageBox.showerror("Warning",message)

        #AND ADD TO THE MASTER DICTIONARY
        self.allover[os.path.basename(datafile)]=newfile
        #UPDATE LIST OF LOADED FILES
        self.overfilelist.append(os.path.basename(datafile))
            
        #UPDATE MAIN WINDOW - LIST OF WAVELENGTHS AND FILES
        self.add_row_over()

#========================================================================

##RUN THE ROUTINE
b=main_win()
b.pack()
b.mainloop() 
