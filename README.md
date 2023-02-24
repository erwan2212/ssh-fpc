# ssh-fpc
Freepascal examples using libssh2 (https://github.com/libssh2/) : a ssh client, a sftp lient. <br/>
Also have a look at https://github.com/erwan2212/dokan-delphi/tree/master/Samples/Proxy_SFTP : the ability to mount a windows logical drive to a remote sftp.</br>
Various libssh2.dll are provided as well (all tested ok) - these can also be found in older php releases here https://windows.php.net/downloads/pecl/releases/ssh2/ .<br/>
Latest libssh2.ll can be found in in php releases here https://windows.php.net/download/ .
<br/><br/>
Also coming along with this project, TinySSL, aka playsing with openssl library (libeay32).<br/>
--genkey                generate rsa keys public.pem and private.pem<br/>
--encrypt               encrypt a file using public.pem<br/>
--decrypt               decrypt a file using private.pem<br/>
--mkcert                make a self sign root cert, read from privatekey (option) & write to ca.crt and ca.key<br/>
--mkreq                 make a certificate service request, read from request.csr (if exist) & write to request.csr request.key<br/>
--signreq               make a certificate from a csr, read from request.csr ca.crt ca.key<br/>
--selfsign              make a self sign cert, write to cert.crt cert.key<br/>
--p12topem              convert a pfx to pem, write to cert.crt and cert.key<br/>
--pemtop12              convert a pem to pfx, read from cert.crt and cert.key<br/>
<br/><br/>

