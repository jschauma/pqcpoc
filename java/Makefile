# Location of BouncyCastle jars.
CP=	"./bc/*:."
JAVAC=	javac -cp ${CP}

.SUFFIXES: .java .class

all:
	@echo "The following targets are available:"
	@echo "client  build the PQTlsClient"
	@echo "server  build the PQTlsServer"
	@echo "clean   remove object files"

client: PQTlsClient.class

server: PQTlsServer.class

.java.class:
	${JAVAC} $<

clean:
	rm -f *.class
