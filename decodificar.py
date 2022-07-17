#/*
# * decodificar.py versión 1.0
# * 
# * Copyright 2020 GICSI. All Rights Reserved.
# *
# * Implementación de engine openssl KLEPTO.
# *
# * THIS SOFTWARE IS PROVIDED "AS IS" AND ANY EXPRESS OR IMPLIED
# * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
# * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR NOR
# * CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
# * SPECIAL, EXEMPLARY, NOR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
# * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
# * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
# * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH
# * DAMAGE.
# *
# */

import cryptography
from scapy.all import *
from Crypto.Cipher import AES
from binascii import unhexlify

# 16 bytes con los que fue xoreada la llave para enviar como iv explícito
XOR_KEY = unhexlify('ffffffffffffffffffffffffffffffff')

# filtrar paquetes de este origen
IP_SRC = '192.168.0.104'


# carga para scapy, para interpretar TLS
load_layer('tls')

# iteración principal
packets = rdpcap("../captura.pcap")
for packet in packets:
    # filtro por dirección IP de origen
    if packet[IP].src == IP_SRC:
        # paquetes que incluyen records TLS
        if TLS in packet:
            i = 0
            # proceso iterativo de records en un mismo paquete (problema en scapy)
            while True:
                try:
                    if hasattr(packet[TLS][i], 'msg'):
                        msg = packet[TLS][i].msg[0]
                        # scapy interpreta como Raw este tipo
                        if (type(msg) == Raw):
                            eiv = msg.load[:16]
                            print('IV explícito: ', eiv)
                            llave = bytes(a ^ b for a, b in zip(XOR_KEY, eiv))
                            print('llave: ', llave)
                        # tipo application data tiene este atributo
                        if hasattr(msg, 'data'):
                            data = msg.data
                            print('data: ', data)
                            # cualquier iv, porque se descarta primer bloque; rfc tls 1.1 - 6.2.3.2 - (2)(b)
                            decipher = AES.new(llave, AES.MODE_CBC, unhexlify('00000000000000000000000000000000'))
                            claro = decipher.decrypt(data)[16:]
                            print('decifrado: ', claro)

                    i += 1

                except IndexError:
                    break


