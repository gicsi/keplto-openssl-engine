#/*
# * Makefile versión 1.1
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


CC	= gcc
CFLAGS	= -fPIC -g -O0 -Wall -Wextra -DERRORMSGS=1 -DDEBUGMSGS=1
#CFLAGS	= -fPIC -O2 -DERRORMSGS=0 -DDEBUGMSGS=0
LIBS	= -lcrypto

libklepto.so: klepto.o
	$(CC) -shared -o libklepto.so klepto.o $(LIBS)

klepto.o: klepto.c klepto.h
	$(CC) -c $(CFLAGS) klepto.c

install:
	cp libklepto.so /usr/lib/libklepto.so

test:
	dd if=/dev/zero of=test.data bs=512 count=1
	# hexdump test.data
	openssl enc -e -aes-128-cbc -in test.data -out test.data.crypt -engine klepto -nosalt -K 00000000000000000000000000000001 -iv 00000000000000000000000000000002
	# hexdump test.data.crypt
	openssl enc -e -aes-128-cbc -in test.data -out test.data.crypt.sin_engine -nosalt -K 00000000000000000000000000000001 -iv 00000000000000000000000000000002
	# hexdump test.data.sin_engine
	diff test.data.crypt test.data.crypt.sin_engine
	#openssl enc -d -aes-128-cbc -in test.data.crypt -out test.data.decrypt -engine klepto -nosalt -K 00000000000000000000000000000001 -iv #00000000000000000000000000000002
	#diff test.data test.data.decrypt

clean:
	rm *.o libklepto.so test.data*
