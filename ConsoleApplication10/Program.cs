using System;
using System.IO;
using System.Drawing;
using System.Drawing.Imaging;
using System.Collections.Generic;
using System.Net.Sockets;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using WIA;

namespace ConsoleApplication10
{
    class Program
    {
        static Socket serverSocket = new Socket(AddressFamily.InterNetwork,
        SocketType.Stream, ProtocolType.IP);
        static private string guid = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
        [System.Runtime.InteropServices.DllImport("user32.dll")]
        private extern static int ShowWindow(System.IntPtr hWnd, int nCmdShow);

        static void Main(string[] args)
        {
            ShowWindow(System.Diagnostics.Process.GetCurrentProcess().MainWindowHandle, 0);
            serverSocket.Bind(new IPEndPoint(IPAddress.Any, 9000));
            serverSocket.Listen(128);
            serverSocket.BeginAccept(null, 0, OnAccept, null);
            //Console.WriteLine("Servicio de scanner UATF (Sistema de escaneo de documentos UATF)");
            //Console.WriteLine("Por favor no cierre esta ventana mientras escanea documentos...");
            
            Console.Read();
            Thread.Sleep(System.Threading.Timeout.Infinite);
        }
        
        private static Byte[] CodificarMensajeParaEnviar(String message)
        {
            Byte[] response;
            Byte[] bytesRaw =System.Text.Encoding.UTF8.GetBytes(message);
            Byte[] frame = new Byte[10];

            Int32 indexStartRawData = -1;
            Int32 length = bytesRaw.Length;

            frame[0] = (Byte)129;
            if (length <= 125)
            {
                frame[1] = (Byte)length;
                indexStartRawData = 2;
            }
            else if (length >= 126 && length <= 65535)
            {
                frame[1] = (Byte)126;
                frame[2] = (Byte)((length >> 8) & 255);
                frame[3] = (Byte)(length & 255);
                indexStartRawData = 4;
            }
            else
            {
                frame[1] = (Byte)127;
                frame[2] = (Byte)((length >> 56) & 255);
                frame[3] = (Byte)((length >> 48) & 255);
                frame[4] = (Byte)((length >> 40) & 255);
                frame[5] = (Byte)((length >> 32) & 255);
                frame[6] = (Byte)((length >> 24) & 255);
                frame[7] = (Byte)((length >> 16) & 255);
                frame[8] = (Byte)((length >> 8) & 255);
                frame[9] = (Byte)(length & 255);

                indexStartRawData = 10;
            }

            response = new Byte[indexStartRawData + length];

            Int32 i, reponseIdx = 0;

            for (i = 0; i < indexStartRawData; i++)
            {
                response[reponseIdx] = frame[i];
                reponseIdx++;
            }

            for (i = 0; i < length; i++)
            {
                response[reponseIdx] = bytesRaw[i];
                reponseIdx++;
            }

            return response;
        }

        private static void OnAccept(IAsyncResult result)
        {
            byte[] buffer = new byte[1024];
            try
            {
                Socket client = null;
                string headerResponse = "";
                if (serverSocket != null && serverSocket.IsBound)
                {
                    client = serverSocket.EndAccept(result);
                    var i = client.Receive(buffer);
                    headerResponse = (System.Text.Encoding.UTF8.GetString(buffer)).Substring(0, i);
                    Console.WriteLine(headerResponse);

                }
                if (client != null)
                {
                    var key = headerResponse.Replace("ey:", "`")
                              .Split('`')[1]                     
                              .Replace("\r", "").Split('\n')[0]  
                              .Trim();

                    var test1 = AcceptKey(ref key);

                    var newLine = "\r\n";

                    var response = "HTTP/1.1 101 Switching Protocols" + newLine
                         + "Upgrade: websocket" + newLine
                         + "Connection: Upgrade" + newLine
                         + "Sec-WebSocket-Accept: " + test1 + newLine + newLine;
                    client.Send(System.Text.Encoding.UTF8.GetBytes(response));

                    var i = client.Receive(buffer);
                    //Console.WriteLine("Iniciando escanneo");
                    string msasd = "";
                    try
                    {
                        List<string> devices = WIAScanner.GetDevices();
                        ICommonDialog instance = (ICommonDialog)Activator.CreateInstance(Type.GetTypeFromCLSID(new Guid("850D1D11-70F3-4BE5-9A11-77AA6B2BB201")));
                        
                        Device device = instance.ShowSelectDevice(WiaDeviceType.UnspecifiedDeviceType, true, false);
                        if (device != null)
                        {
                            List<Image> images = WIAScanner.Scan(device.DeviceID);
                            foreach (Image image in images)
                            {
                                Bitmap objBitmap = new Bitmap(image, new Size(1250, 1550));
                                MemoryStream ms = new MemoryStream();
                                objBitmap.Save(ms, ImageFormat.Jpeg);
                                msasd = Convert.ToBase64String(ms.ToArray());
                            }
                        }
                    }
                    catch (Exception exc)
                    {
                        //
                    }
                    //Console.WriteLine("Escaneo Terminado...");
                    //Console.WriteLine("Escaneo Terminado...");
                    //Console.WriteLine("Iniciando Envio de paquete");
                    int particion = msasd.Length / 100;
                    int mod = msasd.Length % 100;
                    for (int l = 0; l < 100; l++)
                    {
                        byte[] Bytes = CodificarMensajeParaEnviar(msasd.Substring(particion*l,particion));
                        int k = client.Send(Bytes, Bytes.Length, SocketFlags.None);
                        
                    }
                    if (mod != 0)
                    {
                        byte[] Bytes2 = CodificarMensajeParaEnviar(msasd.Substring(particion * 100));
                        int k2 = client.Send(Bytes2, Bytes2.Length, SocketFlags.None);
                    }
                    else {
                        byte[] Bytes2 = CodificarMensajeParaEnviar("");
                        int k2 = client.Send(Bytes2, Bytes2.Length, SocketFlags.None);
                    }
                    //Console.WriteLine("Envio Terminado");
                    //Console.WriteLine("Se enviaron {0} bytes de informacion", msasd.Length);
                }
            }
            catch (SocketException exception)
            {
                throw exception;
            }
            finally
            {
                if (serverSocket != null && serverSocket.IsBound)
                {
                    serverSocket.BeginAccept(null, 0, OnAccept, null);
                }
            }
        }

        public static T[] SubArray<T>(T[] data, int index, int length)
        {
            T[] result = new T[length];
            Array.Copy(data, index, result, 0, length);
            return result;
        }

        private static string AcceptKey(ref string key)
        {
            string longKey = key + guid;
            byte[] hashBytes = ComputeHash(longKey);
            return Convert.ToBase64String(hashBytes);
        }

        static SHA1 sha1 = SHA1CryptoServiceProvider.Create();
        private static byte[] ComputeHash(string str)
        {
            return sha1.ComputeHash(System.Text.Encoding.ASCII.GetBytes(str));
        }
    }
}