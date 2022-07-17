## OpenSSL "Klepto" engine

### Ejemplo de Ataque por Sustitución de Algoritmo

Bellare, Paterson y Rogaway * introducen el concepto de ataques por sustitución de algoritmo, o Algorithm-Substitution Attacks (ASAs). En ese trabajo, motivados por las revelaciones sobre la vigilancia masiva de las comunicaciones encriptadas, formalizan e investigan la resistencia de los esquemas de cifrado simétrico. El foco está puesto en ataques de sustitución de algoritmos (ASA), donde un algoritmo de cifrado subvertido reemplaza al real. Suponen que el objetivo del atacante –a quién llaman “big brother”- es la subversión indetectable, lo que significa que los textos cifrados producidos por el algoritmo de cifrado subvertido deben revelar los textos en claro al atacante y, sin embargo, ser indistinguibles de los producidos por el esquema de cifrado real para los usuarios.
Se formalizaron nociones de seguridad para capturar ese objetivo y luego ofrecen detalles acerca de ataques y defensas. Explicitan que los ASA se pueden montar en una gran clase de esquemas de cifrado simétrico.
Como recuerdan los autores, los ASA se han tratado antes bajo varios nombres, abarcados en el concepto de kleptografía. Mientras algunos criptógrafos parecen haber desestimado inicialmente a la kleptografía, revelaciones recientes sugieren que esta actitud resultó ser ingenua. Los ASA pueden estar sucediendo en la actualidad, posiblemente en una escala masiva.
De acuerdo con el primero de los dos tipos de ataque descriptos, donde además se cita como ejemplo la aplicación al algoritmo AES con 128 bits de llave en modo de operación CBC (Cipher Block Chaining), los autores muestran que los esquemas de cifrado sin estado son típicamente subvertibles. El tipo de ataque mencionado aplica a algoritmos de cifrado simétrico utilizando modos de operación que evidencian o exponen su vector de inicialización, o IV, por sus siglas del inglés, Initialization Vector.
En el ejemplo presentado, se implemntó, mediante un motor o engine OpenSSL, una versión “kleptográfica” del alogirtimo AES 128 en modo CBC.

```
$ echo "GET /" | openssl s_client -ign_eof -tls1_2 -cipher \
AES128-SHA -connect www.google.com:443 -servername www.google.com
```

```
$ python decodificar.py
IV explícito: b'\xdf\xbeQ\xfd\xcd\xc41\xae9L\xf0\xc7\rk\x15\t'
llave: b' A\xae\x022;\xceQ\xc6\xb3\x0f8\xf2\x94\xea\xf6'
data: b"\xbc)Q\xe7\\\xab\x17`...
decifrado: b'GET /...\x05\x05\x05\x05\x05'
```

* Bellare M., Paterson K.G., Rogaway P. "Security of Symmetric Encryption against Mass Surveillance." Advances in Cryptology. CRYPTO 2014. Lecture Notes in Computer Science, vol 8616. Springer, Berlin, Heidelberg (2014).

