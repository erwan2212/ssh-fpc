rem 1.
rem if you want to reuse an existing key and therefore renew instead of (re)create the root ca
tinySSL.exe --mkcert --debug=true --privatekey=ca.key --password=password --filename=ca.crt cn="_Root Authority_"
rem or simply (re)create a root ca, not renew it - you will be prompted to provide a password
rem tinySSL.exe --mkcert --debug=true --filename=ca.crt cn="_Root Authority_"
rem 2.
rem renew your device csr (and later cert), not (re)create it
tinySSL.exe --mkreq --debug=true --filename=request.csr --privatekey=request.key cn="localhost"
rem or simply (re)create your device csr (later cert), not renew it
rem tinySSL.exe --mkreq --debug=true --filename=request.csr cn="localhost"
rem 3.
rem finally, sign your csr - you need your root ca private key password
tinySSL.exe --signreq --debug=true --alt="DNS:*.groupe.fr" --password=password --filename=request.csr --cert=ca.crt