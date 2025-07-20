all: pqcpoc

linux: pqcpoc.linux

pqcpoc: pqcpoc.go
	go build $<

pqcpoc.linux: pqcpoc.go
	env GOOS=linux GOARCH=amd64 go build -o $@ $< 

clean:
	rm -f pqcpoc
	rm -f pqcpoc.linux
