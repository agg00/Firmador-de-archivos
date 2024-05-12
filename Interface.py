from ast import Bytes, Compare
from cryptography.fernet import Fernet
import os
import sys
from Crypto.PublicKey import RSA
from hashlib import sha512
import xml.etree.cElementTree as ET
from xml.dom import minidom
import re

#Importamos la libreria que vamos a usar
from cProfile import label
from tkinter import *
from tkinter import commondialog
from turtle import width, window_height, window_width
from typing import Text
import tkinter.messagebox 
from tkinter import filedialog 
from PIL import Image, ImageTk


archivo_abierto1= ""
archivo_abierto2=""
archivo_abierto3=""

publicKey=""
keyPrivate=""
def generarClaves():
    global publicKey
    global keyPrivate
    if(os.path.exists("ruta_clave_publica.pem") == False or os.path.exists("ruta_clave_privada.pem") == False):
        keyRSA = RSA.generate(2048)
        with open("ruta_clave_publica.pem", "wb") as file:
            file.write(keyRSA.public_key().export_key())
    
        publicKey=RSA.import_key(open("ruta_clave_publica.pem").read())

        with open("ruta_clave_privada.pem", "wb") as file:
            file.write(keyRSA.export_key())
    
        keyPrivate=RSA.import_key(open("ruta_clave_privada.pem").read())
        tkinter.messagebox.showinfo("Aviso",  "Claves generadas con éxito.")
    else:
        publicKey=RSA.import_key(open("ruta_clave_publica.pem").read())
        keyPrivate=RSA.import_key(open("ruta_clave_privada.pem").read())
        tkinter.messagebox.showinfo("Aviso",  "Las claves han sido generadas anteriormente.")
    
def leerClaves():
    global publicKey
    global keyPrivate
    publicKey=RSA.import_key(open("ruta_clave_publica.pem").read())
    keyPrivate=RSA.import_key(open("ruta_clave_privada.pem").read())

carpetaFirmas = "DirectorioFirmas"
try:
    os.stat(carpetaFirmas)
except:
    os.mkdir(carpetaFirmas)


def abrirArchivo1():
    global archivo_abierto1
    archivo_abierto1=filedialog.askopenfilename(initialdir="/", title= "Seleccione archivo", filetypes=(("all files", "*.*"),("jpeg files", "*.jpg")))
    archivo_abiertoSplit = archivo_abierto1.split("/")
    etiquetaArchivo_Abierto1 = tkinter.Label(window, text="Archivo seleccionado: " + archivo_abiertoSplit[len(archivo_abiertoSplit)-1],bg="antique white", fg="black", font=("Verdana", 10))
    etiquetaArchivo_Abierto2 = tkinter.Label(window, text="Carpeta del archivo: " + archivo_abiertoSplit[len(archivo_abiertoSplit)-2],bg="antique white", fg="black", font=("Verdana", 10))
    etiquetaArchivo_Abierto1.place(x=14, y =360, width= 350, height=30)
    etiquetaArchivo_Abierto2.place(x=14, y =384, width= 350, height=30)


def abrirArchivo2():
    global archivo_abierto2
    archivo_abierto2=filedialog.askopenfilename(initialdir="/", title= "Seleccione archivo", filetypes=(("all files", "*.*"),("jpeg files", "*.jpg")))
    archivo_abiertoSplit = archivo_abierto2.split("/")
    etiquetaArchivo_Abierto2 = tkinter.Label(window, text="Archivo seleccionado: " + archivo_abiertoSplit[len(archivo_abiertoSplit)-1],bg="antique white", fg="black", font=("Verdana", 10))
    etiquetaArchivo_Abierto3 = tkinter.Label(window, text="Carpeta del archivo: " + archivo_abiertoSplit[len(archivo_abiertoSplit)-2],bg="antique white", fg="black", font=("Verdana", 10))
    etiquetaArchivo_Abierto2.place(x=425, y =360, width= 480, height=30)
    etiquetaArchivo_Abierto3.place(x=425, y =384, width= 480, height=30)


def verClaves():
    #CODIGO DE VER CLAVES 
    #---------------------------
    global publicKey
    global keyPrivate
    leerClaves()
    tkinter.messagebox.showinfo("CLAVE",  publicKey.export_key())

def firmar():
    #CODIGO DE FIRMAR DOCUMENTOS
    #---------------------------
    
    global publicKey
    global keyPrivate
    global carpetaFirmas
    global archivo_abierto1
    carpetaFirmas2 = carpetaFirmas
    carpetaFirmasExtensionIguales = carpetaFirmas
    if os.path.exists("ruta_clave_privadaEncriptada.pem") is True:
        tkinter.messagebox.showinfo("Aviso", "Para firmar un archivo tiene que desencriptar la clave privada haciendo uso del programa <DesencriptarClave.exe>, ubicado en la carpeta de Documentos.")
    else:
        leerClaves()



    with open(archivo_abierto1, "rb") as file:
        contenido = file.read()
    hash = int.from_bytes(sha512(contenido).digest(), byteorder='big')
    signature = pow(hash, keyPrivate.d, publicKey.n)
    root = ET.Element("root")
    doc = ET.SubElement(root, "doc")
    nodo1=ET.SubElement(doc, "nodo1", name="nodo")
    nodo1.text="Firma:"
    ET.SubElement(doc, "nodo2", atributo="firma").text = str(signature)
    
    arbol = ET.ElementTree(root)
    localizacion = archivo_abierto1.split("/")
    fichero = localizacion[len(localizacion)-1]
    fichero2=fichero.split(".")
    fichero2[0]+="Firmado"
    ET.SubElement(doc, "nodo3", atributo="extension").text = fichero2[1]
    extension = fichero2[1].removesuffix(fichero2[1])
    extension+=".xml"
    archivoXMLIguales = fichero2[0]
    archivoXML = fichero2[0]+extension
    carpetaFirmas2+="\\"+archivoXML
    os.path.isfile(carpetaFirmas2)
        
    if os.path.isfile(carpetaFirmas2) is True:
        tkinter.messagebox.showinfo("Aviso", "El archivo <" + fichero + "> ya había sido firmado.")
    else:
        arbol.write(carpetaFirmas2)
        tkinter.messagebox.showinfo("Aviso", "El archivo <" + fichero + "> ha sido firmado.")
        archivo_abierto1 = ""
   
def comprobarExtensiones():
    leerClaves()
    global publicKey
    global keyPrivate
    global carpetaFirmas
    global archivo_abierto1
    carpetaFirmasExtensionIguales = carpetaFirmas
    localizacion = archivo_abierto1.split("/")
    fichero = localizacion[len(localizacion)-1]
    fichero2=fichero.split(".")
    nombreFichero = fichero2[0]
    extensionFichero = fichero2[1]
    fichero2[0]+="Firmado"
    extension = fichero2[1].removesuffix(fichero2[1])
    extension+=".xml"
    archivoXML = fichero2[0] + extension
     
    carpetaFirmasExtensionIguales +="\\"+archivoXML
    # archivoXML = fichero2[0]+extension
    # carpetaFirmas2+="\\"+archivoXML
    arbol = ET.parse(carpetaFirmasExtensionIguales)
    root = arbol.getroot()
    for c in root.findall('doc'):
        extension2 = c.find('nodo3').text
    
    if fichero2[1] != extension2:
        archivoXMLExt = nombreFichero + extensionFichero + "Firmado"
        archivoXMLExt += ".xml"
        carpetaExt =carpetaFirmas + "\\"+archivoXMLExt
        root = ET.Element("root")
        doc = ET.SubElement(root, "doc")
        nodo1=ET.SubElement(doc, "nodo1", name="nodo")
        nodo1.text="Firma:"
        with open(archivo_abierto1, "rb") as file:
            contenido = file.read()
        hash = int.from_bytes(sha512(contenido).digest(), byteorder='big')
        signature = pow(hash, keyPrivate.d, publicKey.n)
        ET.SubElement(doc, "nodo2", atributo="firma").text = str(signature)
        ET.SubElement(doc, "nodo3", atributo="extension").text = fichero2[1]
        arbol2 = ET.ElementTree(root)
        arbol2.write(carpetaExt)
        tkinter.messagebox.showinfo("Aviso", "El archivo <" + fichero + "> ha sido firmado.")
        return False
        

def validar():
    #CODIGO DE VALIDAR DOCUMENTOS
    #---------------------------
    leerClaves()
    global publicKey
    global keyPrivate
    global carpetaFirmas
    global archivo_abierto2
    carpetaFirmas2=carpetaFirmas

    archivo_abiertoX=archivo_abierto2
    with open(archivo_abiertoX, "rb") as file:
        contenido = file.read()  

    # with open(archivo_abierto3, "rb") as file:
    #     contenido2 = file.read()  
    localizacion = archivo_abiertoX.split("/")
    fichero = localizacion[len(localizacion)-1]
    fichero2=fichero.split(".")
    fichero2[0]+="Firmado"
    extension = fichero2[1].removesuffix(fichero2[1])
    extension+=".xml"
    archivoXML = fichero2[0]+extension

    carpetaFirmas2 += "\\"+archivoXML
    
    # carpetaFirmas[len(carpetaFirmas)-1]=archivoXML
    # result=""
    # for s in localizacion:
    #     result+=s+"/"
    # result=result[:-1]
    
    
    
    # carpetaFirmas = result.split("/")
    # fichero3 = carpetaFirmas[len(carpetaFirmas)-1]
    arbol=""
    rank=""
    try:
        arbol = ET.parse(carpetaFirmas2)
        root = arbol.getroot()

        for c in root.findall('doc'):
            rank = c.find('nodo2').text
    except FileNotFoundError:
        tkinter.messagebox.showinfo("Aviso",  "El archivo <" + str(fichero) + "> no está firmado.\nPor favor, fírmelo para poder validarlo.")
    
    

    hash2 = int.from_bytes(sha512(contenido).digest(), byteorder='big')
    hashFromSignature = pow(int(rank), publicKey.e, publicKey.n)
    archivo_abiertoX=""
    
    try:
        file=open(carpetaFirmas2)
        if hash2 == hashFromSignature:
            tkinter.messagebox.showinfo("Aviso",  "El archivo <" + str(fichero) + "> es válido.")
        else:
            tkinter.messagebox.showinfo("Aviso",  "El archivo <" + str(fichero) + "> no es válido.")
    except FileNotFoundError:
        tkinter.messagebox.showinfo("Aviso",  "El archivo <" + str(fichero) + "> no está firmado.")
    carpetaFirmas2=""
        
    
def comprobarFicheros():
    leerClaves()
    global publicKey
    global keyPrivate
    global carpetaFirmas
    global archivo_abierto2
    carpetaFirmas2=carpetaFirmas
    archivo_abiertoX = archivo_abierto2
    with open(archivo_abiertoX, "rb") as file:
        contenido = file.read()
    carpetaFirmasExtensionIguales = carpetaFirmas2
    localizacion = archivo_abiertoX.split("/")
    fichero = localizacion[len(localizacion)-1]
    fichero2=fichero.split(".")
    nombreFichero = fichero2[0]
    extensionFichero = fichero2[1]
    fichero2[0]+= extensionFichero + "Firmado"
    extension = fichero2[1].removesuffix(fichero2[1])
    extension+=".xml"
    archivoXML = fichero2[0] + extension
     
    carpetaFirmasExtensionIguales +="\\"+archivoXML
    arbol=""
    rank=""
    try:
        arbol = ET.parse(carpetaFirmasExtensionIguales)
        root = arbol.getroot()

        for c in root.findall('doc'):
            rank = c.find('nodo2').text
    except FileNotFoundError:
        tkinter.messagebox.showinfo("Aviso",  "El archivo <" + str(fichero) + "> no está firmado.")
    
    
    hash2 = int.from_bytes(sha512(contenido).digest(), byteorder='big')
    hashFromSignature = pow(int(rank), publicKey.e, publicKey.n)
    archivo_abiertoX=""
    
    try:
        file=open(carpetaFirmasExtensionIguales)
        if hash2 == hashFromSignature:
            tkinter.messagebox.showinfo("Aviso",  "El archivo <" + str(fichero) + "> es válido.")
            carpetaFirmasExtensionIguales=""
            carpetaFirmas2=""
        else:
            tkinter.messagebox.showinfo("Aviso",  "El archivo <" + str(fichero) + "> no es válido.")
            carpetaFirmasExtensionIguales=""
            carpetaFirmas2=""
    except FileNotFoundError:
        tkinter.messagebox.showinfo("Aviso",  "El archivo <" + str(fichero) + "> no está firmado.")
        carpetaFirmasExtensionIguales=""
        carpetaFirmas2=""
    

window=tkinter.Tk()
window.title("APLICACION")
window.geometry("850x600")
window.config(bg="antique white")

image = Image.open("imagenAplicacion.png")
image = image.resize((130,130), Image.ANTIALIAS)
img = ImageTk.PhotoImage(image)
lbl_img = Label(window,image=img,bg="NavajoWhite3").place(x=0,y=0,width= 200, height=130)

etiquetaFirmar = tkinter.Label(window, text="FIRMAR ARCHIVOS",bg="antique white", fg="black", font=("Times New Roman", 18))
etiquetaFirmar.place(x=80, y =200, width= 215, height=30)

etiquetaSeleccionarArchivo1 = tkinter.Label(window, text="Seleccione el archivo: ",bg="antique white", fg="black", font=("Verdana", 10))
etiquetaSeleccionarArchivo1.place(x=25, y =280, width= 200, height=30)

etiquetaSeleccionarArchivo2 = tkinter.Label(window, text="Seleccione el archivo: ",bg="antique white", fg="black", font=("Verdana", 10))
etiquetaSeleccionarArchivo2.place(x=470, y =280, width= 220, height=30)

# etiquetaSeleccionarArchivo3 = tkinter.Label(window, text="Seleccione el segundo archivo: ",bg="antique white", fg="black", font=("Verdana", 10))
# etiquetaSeleccionarArchivo3.place(x=470, y =330, width= 220, height=30)

etiquetaVerificar = tkinter.Label(window, text="VALIDAR ARCHIVOS",bg="antique white", fg="black", font=("Times New Roman", 18))
etiquetaVerificar.place(x=540, y =200, width= 250, height=30)

titulo = tkinter.Label(window, text="IDENTIFICADOR DE ARCHIVOS",bg="NavajoWhite3", fg="black", font=("Times New Roman", 25))
titulo.place(x=200, y =0, width= 500, height=130)

fondo = tkinter.Label(window, bg="NavajoWhite3")
fondo.place(x=700, y =0, width= 150, height=130)

botonFirmar= Button (window, text= "Firmar" , fg="black" , font=("Verdana", 12), command= firmar) 
botonFirmar.place(x=110, y =450, width= 150, height=50)

botonSeleccionarExt= Button (window, text= "*" , fg="black" , font=("Verdana", 10), command= comprobarExtensiones) 
botonSeleccionarExt.place(x=240, y =450, width= 20, height=30)

botonValidar= Button (window, text= "Validar" , fg="black" , font=("Verdana", 12), command= validar) 
botonValidar.place(x=590, y =450, width= 150, height=50)

botonValidarExt= Button (window, text= "*" , fg="black" , font=("Verdana", 12), command= comprobarFicheros) 
botonValidarExt.place(x=720, y =450, width= 20, height=30)

botonVerclaves= Button (window, text= "Ver clave" , fg="black" , font=("Verdana", 10), command= verClaves) 
botonVerclaves.place(x=380, y =560, width= 100, height=35)

botonGenerarClaves= Button (window, text= "Generar claves" , fg="black" , font=("Verdana", 10), command= generarClaves) 
botonGenerarClaves.place(x=250, y =560, width= 110, height=35)

botoncerrar= Button (window, text= "Cerrar" , fg="black" , font=("Verdana", 10), command= window.destroy) 
botoncerrar.place(x=500, y =560, width= 100, height=35)

botonSeleccionar1= Button (window, text= "Seleccionar" , fg="black" , font=("Verdana", 10), command= abrirArchivo1) 
botonSeleccionar1.place(x=220, y =280, width= 120, height=30)



botonSeleccionar2= Button (window, text= "Seleccionar" , fg="black" , font=("Verdana", 10), command= abrirArchivo2) 
botonSeleccionar2.place(x=675, y =280, width= 120, height=30)

window.mainloop()
