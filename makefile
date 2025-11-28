ipcap: clean
	cc main.c ipv4.c -o ipcap

run: clean ipcap
	./ipcap

clean:
	rm -f ipcap