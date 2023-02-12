program ssh;

//libss2 available here  https://windows.php.net/downloads/pecl/releases/ssh2/
//openssl here https://indy.fulgan.com/SSL/
//see definition here https://github.com/libssh2/libssh2/blob/master/include/libssh2.h
//see examples here https://github.com/libssh2/libssh2/tree/master/example

{$mode objfpc}{$H+}
{$APPTYPE CONSOLE}

uses
  {$IFDEF UNIX}
  cthreads,
  {$ENDIF}
  windows,sysutils,classes,
  libssh2,
  winsock2,
  libeay32,
  rcmdline in '..\rcmdline-master\rcmdline.pas';

type
ReadKeyChar = AnsiChar;
//ReadKeyChar = Byte;
PReadKeyChar = ^ReadKeyChar;

type

  { TMyThread }

  TReadThread=class(TThread)
    private
      FChannel:PLIBSSH2_CHANNEL;
    protected
      procedure Execute; override;
    public
      constructor Create(channel_:PLIBSSH2_CHANNEL);
    end;

  Type
  TArrayStr = Array Of string;


var
  debug:boolean=false;
  bNewString:boolean;
  ssend:string;
  delay:integer;
  //
  host,username,password,command,pty,privatekey,publickey,local_filename,remote_filename:string;
  port:integer=22;
  //
  cmd: TCommandLineReader;

procedure log(msg:string;level:byte=0);
begin
if (level=0) and (debug=false) then exit;
writeln(msg);
end;

procedure LoadSSL;
begin
  OpenSSL_add_all_algorithms;
  OpenSSL_add_all_ciphers;
  OpenSSL_add_all_digests;
  ERR_load_crypto_strings;
  ERR_load_RSA_strings;
end;


procedure FreeSSL;
begin
  EVP_cleanup;
  ERR_free_strings;
end;

//openssl pkcs12 -inkey priv.pem -in cert.pem -export -out cert.pfx
function mkcert:boolean;
var
    pkey:PEVP_PKEY;
    rsa:pRSA;
    x509:pX509;
    name:pX509_NAME;
    hfile:thandle=thandle(-1);
    f:file;
    bp:pBIO;
begin
result:=false;
  //OpenSSL provides the EVP_PKEY structure for storing an algorithm-independent private key in memory
  log('EVP_PKEY_new');
  pkey := EVP_PKEY_new();
  //generate key
  log('RSA_generate_key');
rsa := RSA_generate_key(
    2048,   //* number of bits for the key - 2048 is a sensible value */
    RSA_F4, //* exponent - RSA_F4 is defined as 0x10001L */
    nil,   //* callback - can be NULL if we aren't displaying progress */
    nil    //* callback argument - not needed in this case */
);
//assign key to our struct
log('EVP_PKEY_assign_RSA');
//EVP_PKEY_assign_RSA(pkey, rsa);
EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
//OpenSSL uses the X509 structure to represent an x509 certificate in memory
log('X509_new');
x509 := X509_new();
//Now we need to set a few properties of the certificate
ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
//
X509_gmtime_adj(X509_get_notBefore(x509), 0);
X509_gmtime_adj(X509_get_notAfter(x509), 31536000);
//Now we need to set the public key for our certificate using the key we generated earlier
log('X509_set_pubkey');
X509_set_pubkey(x509, pkey);
//Since this is a self-signed certificate, we set the name of the issuer to the name of the subject
log('X509_get_subject_name');
name := X509_get_subject_name(x509);
X509_NAME_add_entry_by_txt(name, 'C',  MBSTRING_ASC,pchar('FR'), -1, -1, 0);
X509_NAME_add_entry_by_txt(name, 'O',  MBSTRING_ASC,pchar('MyCompany Inc.'), -1, -1, 0);
X509_NAME_add_entry_by_txt(name, 'CN', MBSTRING_ASC,pchar('localhost'), -1, -1, 0);
//Now we can actually set the issuer name:
log('X509_set_issuer_name');
X509_set_issuer_name(x509, name);
//And finally we are ready to perform the signing process. We call X509_sign with the key we generated earlier. The code for this is painfully simple:
log('X509_sign');
X509_sign(x509, pkey, EVP_sha1());

//write out to disk

//hfile := CreateFile(pchar('priv.pem'), GENERIC_READ or generic_write , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, create_always , FILE_ATTRIBUTE_NORMAL, 0);
//if hfile=thandle(-1) then begin log('invalid handle',1);exit;end;
{
AssignFile(f, 'priv.pem');
ReWrite(f);
log('PEM_write_PrivateKey');
PEM_write_PrivateKey(
    f,              //* write the key to the file we've opened */
    pkey,               //* our key from earlier */
    EVP_des_ede3_cbc(), //* default cipher for encrypting the key on disk */
    nil,       //* passphrase required for decrypting the key on disk */
    0,                 //* length of the passphrase string */
    nil,               //* callback for requesting a password */
    nil                //* data to pass to the callback */
);
//closehandle(hfile);

hfile := CreateFile(pchar('cert.pem'), GENERIC_READ or generic_write , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, create_always , FILE_ATTRIBUTE_NORMAL, 0);
if hfile=thandle(-1) then begin log('invalid handle',1);exit;end;
log('PEM_write_X509');
PEM_write_X509(
    hfile,   //* write the certificate to the file we've opened */
    x509    //* our certificate */
);
}
bp := BIO_new_file(pchar(GetCurrentDir+'\priv.pem'), 'w+');
//PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),pchar(''),0,nil,nil);
//if you want a prompt for passphrase
PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);
bp := BIO_new_file(pchar(GetCurrentDir+'\cert.pem'), 'w+');
PEM_write_bio_X509(bp,x509);
//
//bp := BIO_new_file(pchar(GetCurrentDir+'\cert.crt'), 'w+');
//PEM_write_bio_X509(bp,x509);
//PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);
//
result:=true;
end;

function LoadPEMFile(filePath: string): PBio;
var
{$IFNDEF MSWINDOWS}
  LEncoding: TEncoding;
  LOffset: Integer;
{$ENDIF}
  Buffer: TBytes;
  Stream: TStream;
begin
  Stream := TFileStream.Create(filePath, fmOpenRead or fmShareDenyWrite);
  try
    SetLength(Buffer, Stream.size);
    Stream.ReadBuffer(Buffer[0], Stream.size);
{$IFNDEF MSWINDOWS}
{On traite les problèmes d'encodage de flux sur les plateformes différentes de Windows}
    LEncoding := nil;
    LOffset := TEncoding.GetBufferEncoding(Buffer, LEncoding);
    Buffer := LEncoding.Convert(LEncoding, TEncoding.UTF8, Buffer, LOffset,
      Length(Buffer) - LOffset);
{$ENDIF}
    Result := BIO_new_mem_buf(@Buffer[0], Length(Buffer));
  finally
    Stream.free;
  end;
end;

{
Importer une clé publique RSA
Un fichier au format PEM contenant une clé publique RSA
commence par —–BEGIN PUBLIC KEY—–
puis est suivi de la clé en Base64
et se termine par —–END PUBLIC KEY—–.
}
function FromOpenSSLPublicKey(filePath: string): pRSA;
var
  KeyBuffer: PBIO;
  pkey: PEVP_PKEY;
  x: pEVP_PKEY;
begin
  x:=nil;
  KeyBuffer := LoadPEMFile(filePath);
  if KeyBuffer = nil then
    raise Exception.Create('Impossible de charger le buffer');
  try
    pkey := PEM_read_bio_PUBKEY(KeyBuffer, x, nil, nil);
    if not Assigned(pkey) then
      raise Exception.Create('Impossible de charger la clé publique');
    try
      Result := EVP_PKEY_get1_RSA(pkey);
      if not Assigned(Result) then
        raise Exception.Create('Impossible de charger la clé publique RSA');
    finally
      EVP_PKEY_free(pkey);
    end;
  finally
    BIO_free(KeyBuffer);
  end;
end;
{
Importer une clé privée RSA (chiffrée ou non)
Un fichier au format PEM contenant un clé privée RSA
commence par —–BEGIN PRIVATE KEY—– puis est suivi de la clé en Base64
et se termine par —–END PRIVATE KEY—–.
Si la clé est chiffrée, alors le fichier au format PEM
commence par —–BEGIN RSA PRIVATE KEY—– puis est suivi de Proc-Type: 4,ENCRYPTED.
Ensuite, il y a des informations sur l’algorithme utilisé pour chiffrer la clé (par exemple AES-128-CBC)
puis il y a la clé chiffrée, en Base64.
Enfin, le fichier se termine par —–END RSA PRIVATE KEY—–.
}
function FromOpenSSLPrivateKey(filePath: string; pwd: String): pRSA;
var
  KeyBuffer: PBio;
  p: PReadKeyChar;
  I: Integer;
  x: pRSA;
begin
  x:=nil;
  KeyBuffer := LoadPEMFile(filePath);
  if KeyBuffer = nil then
    raise Exception.Create('Impossible de charger le buffer');
  try
    if pwd <> '' then
    begin
      p := GetMemory((length(pwd) + 1) * SizeOf(Char));
      for I := 0 to length(pwd) - 1 do p[I] := ReadKeyChar(pwd[I+1]);
      p[length(pwd)] := ReadKeyChar(#0);
    end
    else
      p := nil;
    try
      Result := PEM_read_bio_RSAPrivateKey(KeyBuffer, x, nil, p);
      if not Assigned(Result) then
        raise Exception.Create('Impossible de charger la clé privée RSA');
    finally
{On efface le mot de passe}
      FillChar(p, SizeOf(p), 0);
      FreeMem(p);
    end;
  finally
    BIO_free(KeyBuffer);
  end;

end;

{
Importer une clé publique RSA à partir d’un certificat X509
Un fichier au format PEM contenant un certificat X509
commence par —–BEGIN CERTIFICATE—– puis est suivi de la clé en Base64
et se termine par —–END CERTIFICATE—–.
}
function FromOpenSSLCert(filePath: string): pRSA;
var
  KeyBuffer: PBIO;
  FX509: pX509;
  Key: PEVP_PKEY;
  x: pX509;
begin
  x:=nil;
  //KeyBuffer := LoadPEMFile(Buffer, Length(Buffer));
  KeyBuffer := LoadPEMFile(filepath);
  if KeyBuffer = nil then
    raise Exception.Create('Impossible de charger le buffer X509');
  try
    FX509 := PEM_read_bio_X509(KeyBuffer, x, nil, nil);
    if not Assigned(FX509) then
      raise Exception.Create('Impossible de charger le certificat X509');
    Key := X509_get_pubkey(FX509);
    if not Assigned(Key) then
      raise Exception.Create('Impossible de charger la clé publique X509');
    try
      Result := EVP_PKEY_get1_RSA(Key);
      if not Assigned(Result) then
        raise Exception.Create('Impossible de charger la clé publique RSA');
    finally
      EVP_PKEY_free(Key);
    end;
  finally
    BIO_free(KeyBuffer);
  end;
end;

//on the remote ssh server, generate the pub key from the private key generated on the client
//ssh-keygen -y -f private.pem > key.pub
//copy the pub key to the authorized keys
//cat key.pub >> ~/.ssh/authorized_keys
//should work as well : ssh-copy-id -i /path/to/key/file user@host.com
//Remember that .ssh folder has to be 700. The authorized_keys file should be 600
//or the other way (no success here for now)
//on the remote ssh server, generate a key pair
//ssh-keygen -b 2048 -t rsa -m PEM
//and use either the pub or priv key from there
//see also https://docs.oracle.com/en/cloud/cloud-at-customer/occ-get-started/generate-ssh-key-pair.html
function generate_key:boolean;
var

	ret:integer; //= 0;
	r:pRSA;//				 = nil;
	bne:pBIGNUM;// = nil;
	bp_public:pBIO;// = nil;
  bp_private:pBIO;// = nil;

	bits:integer; // = 2048;
	e:ulong; // = RSA_F4;
  label free_all;
begin
  //
  ret:=0;
  r:=nil;
  bne:=nil;
  bp_public :=nil;
  bp_private :=nil;
  bits:=2048;
  e :=RSA_F4;
	// 1. generate rsa key
	bne := BN_new();
	ret := BN_set_word(bne,e);
	if ret <> 1 then goto free_all;

	r := RSA_new();
	ret := RSA_generate_key_ex(r, bits, bne, nil);
	if ret <> 1 then goto free_all;
        log('1. generate rsa key OK');



	// 2. save public key
	bp_public := BIO_new_file(pchar(GetCurrentDir+'\public.pem'), 'w+');
	ret := PEM_write_bio_RSAPublicKey(bp_public, r);
	if ret <>1 then goto free_all;
        log('2. save public key OK');

	// 3. save private key
	bp_private := BIO_new_file(pchar(GetCurrentDir+'\private.pem'), 'w+');
	ret := PEM_write_bio_RSAPrivateKey(bp_private, r, nil, nil, 0, nil, nil);
        log('3. save private key');

	// 4. free
free_all:

	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(r);
	BN_free(bne);

	if ret=1 then result:=true else result:=false;
end;


{ TReadThread }

procedure TReadThread.Execute;
var
  buf:array[0..8192-1] of char;
  len:integer;
begin
  libssh2_channel_set_blocking(fchannel,0);
  while not Terminated do
    begin
    len:=libssh2_channel_read(fchannel,@buf[0],length(buf));
    if len>0 then
      begin
      write(copy(buf,0,len));
      end
    else if bNewString then
      begin
      libssh2_channel_write(fchannel,pchar(ssend),length(ssend));
      bNewString:=false;
      end
    else
      sleep(delay);
    end;
end;

constructor TReadThread.Create(channel_: PLIBSSH2_CHANNEL);
begin
  inherited Create(true);
  FChannel:=channel_;
end;

//previous version was using synapse
//lets switch to winsock2
function init_socket(var sock_:tsocket):boolean;
var
wsadata:TWSADATA;
err:longint;
hostaddr:u_long;
sin:sockaddr_in;
begin
  result:=false;
  //
  err := WSAStartup(MAKEWORD(2, 0), wsadata);
  if(err <> 0) then raise exception.Create ('WSAStartup failed with error: '+inttostr(err));
  //
  hostaddr := inet_addr(pchar(host));
  //
  sock_ := socket(AF_INET, SOCK_STREAM, 0);
  //
  sin.sin_family := AF_INET;
  sin.sin_port := htons(port);
  sin.sin_addr.s_addr := hostaddr;
  if connect(sock_, tsockaddr(sin), sizeof(sockaddr_in)) <> 0
     then raise exception.Create ('failed to connect');
  //
  result:=true;

end;

function SplitString(Text: String;Delimiter : char): TArrayStr;
var
   intIdx: Integer;
   intIdxOutput: Integer;
begin
   intIdxOutput := 0;
   SetLength(Result, 1);
   Result[intIdxOutput] := '';

   for intIdx := 1 to Length(Text) do
   begin
      if Text[intIdx] = Delimiter then
      begin
         intIdxOutput := intIdxOutput + 1;
         SetLength(Result, Length(Result) + 1);
      end
      else
         Result[intIdxOutput] := Result[intIdxOutput] + Text[intIdx];
   end;
end;

procedure Split(const Delimiter: Char; Input: string; const Strings: TStrings);
begin
   Assert(Assigned(Strings)) ;
   Strings.Clear;
   Strings.Delimiter := Delimiter;
   Strings.DelimitedText := Input;
end;

///etc/ssh/sshd_config -> GatewayPorts yes is you want to have the remote port open to the whole word (localhost only by default)
//also check allowtcpforwarding ? seems not needed
//sudo netstat -ap | grep :<port_number> to check port is open on remote ssh server
//direct-tcpip is what ssh -L uses,
//and forward-tcpip is what ssh -R uses.
function forward_tcpip(server_ip,username,password,local_destip:string;local_destport:integer):boolean;
var
   tmp:string;
   rc,sinlen,i:integer;
   sock,forwardsock:TSocket;
   sin:TSockAddr;
   session:PLIBSSH2_SESSION;
   fingerprint,userauthlist:pansichar;
   listener:PLIBSSH2_LISTENER;
   channel:PLIBSSH2_CHANNEL;
   //
   fds:TFDSet;
   tv:timeval;
   len, wr:integer;
   buf:array [0..16384-1] of char;
   //

   //server_ip:string := '127.0.0.1';
   remote_listenhost:string = '0.0.0.0'; //* resolved by the server */
   remote_wantport:integer = 2222;
   //local_destip:string = '127.0.0.1';
   //local_destport:integer = 80;

   remote_listenport:integer=0;
   //
   wsadata:TWSADATA;
   //
   label shutdown;
begin
    //
    rc := WSAStartup(MAKEWORD(2, 0), wsadata);
    if(rc <> 0) then raise exception.Create ('WSAStartup failed with error: '+inttostr(rc));
    //
    log('libssh2_session_init...',1);
    rc := libssh2_init(0);
    if(rc <> 0) then raise exception.create('libssh2 initialization failed');

    //* Connect to SSH server */
    sock := socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock = INVALID_SOCKET)  then raise exception.create('failed to open socket!');

    sin.sin_family := AF_INET;
    sin.sin_addr.s_addr := inet_addr(pchar(server_ip));
    if (INADDR_NONE = sin.sin_addr.s_addr)  then raise exception.create('inet_addr');
    sin.sin_port := htons(22);

    if (connect(sock, sin, sizeof(sockaddr_in)) <> 0) then raise exception.create('failed to connect!');

    //* Create a session instance */
    log('libssh2_session_init...,1');
    session := libssh2_session_init();

    if session=nil then raise exception.create ('Could not initialize SSH session!');

    //* ... start it up. This will trade welcome banners, exchange keys,
    // * and setup crypto, compression, and MAC layers
    // */
    rc := libssh2_session_handshake(session, sock);

    if (rc<>0) then raise exception.create ('Error when starting up SSH session');

    //* At this point we havn't yet authenticated.  The first thing to do
    //     * is check the hostkey's fingerprint against our known hosts Your app
    //     * may have it hard coded, may go to a file, may present it to the
    //     * user, that's your call
    //     */
        fingerprint := libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
        for i:=0 to 19 do tmp:=tmp+inttohex(ord(fingerprint[i]),2)+ ':';
        log('fingerprint:'+tmp);

    ///* check what authentication methods are available */
        userauthlist := libssh2_userauth_list(session, pchar(username), strlen(pchar(username)));

     if libssh2_userauth_password(session, pchar(username), pchar(password))<>0
                then raise exception.create ('Authentication by password failed.');
     {
     if libssh2_userauth_publickey_fromfile(session, username, keyfile1,keyfile2, password)<>0 then ;
                then raise exception.create ('Authentication by public key failed!');
     }

     log('Asking server to listen on remote '+ remote_listenhost + ':' +inttostr(remote_wantport),1);
     listener := libssh2_channel_forward_listen_ex(session, pchar(remote_listenhost), remote_wantport, remote_listenport, 1);
     if listener=nil then raise exception.create ('Could not start the tcpip-forward listener!');

     log('Server is listening on '+ remote_listenhost +':'+ inttostr(remote_listenport),1);

     log('Waiting for remote connection',1);

     channel := libssh2_channel_forward_accept(listener);
     if channel=nil then raise exception.create ('Could not accept connection!');

     log('Accepted remote connection. Connecting to local server '+ local_destip+':'+inttostr(local_destport),1);

     forwardsock := socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
     if forwardsock = INVALID_SOCKET then raise exception.create ('failed to open forward socket!');

     sin.sin_family := AF_INET;
     sin.sin_port := htons(local_destport);
     sin.sin_addr.s_addr := inet_addr(pchar(local_destip));
     if INADDR_NONE = sin.sin_addr.s_addr then raise exception.create ('inet_addr');

     if -1 = connect(forwardsock, sin, sizeof(sockaddr_in)) then raise exception.create ('connect');

     log('Forwarding connection from remote '+ remote_listenhost +':'+inttostr( remote_listenport)+' '+ local_destip+':'+inttostr(local_destport),1);

     //* Must use non-blocking IO hereafter due to the current libssh2 API */
     libssh2_session_set_blocking(session, 0);

     while 1=1 do
       begin
             FD_ZERO(fds);
             FD_SET(forwardsock, fds);
             tv.tv_sec := 0;
             tv.tv_usec := 100000;
             rc := select(forwardsock + 1, @fds, nil, nil, @tv);
             if -1 = rc then
                begin
                log('select');
                goto shutdown;
                end;

             if (rc<>0) and (FD_ISSET(forwardsock, fds)) then
             begin
                 len := recv(forwardsock, @buf[0], sizeof(buf), 0);
                 if(len < 0)
                        then raise exception.create('read')
                        else if (0 = len) then
                        begin
                        log('The local server disconnected!'+local_destip+':'+inttostr(local_destport),1);
                        goto shutdown;
                        end;
                 if len>0 then log('recv:'+inttostr(len)+' bytes');
                 wr := 0;
                 repeat
                     i := libssh2_channel_write(channel, @buf[0], len);
                     if i>0 then log('libssh2_channel_write:'+inttostr(i)+' bytes');
                     if i=len then break; //buffer has been sent
                     if(i < 0) then
                          begin
                          log('libssh2_channel_write: '+inttostr(i));
                          //goto shutdown;
                          break;
                          end;
                     wr := wr+i;
                 until ((i > 0) and (wr < len));

             end; //if (rc<>0) and (FD_ISSET(forwardsock, fds)) then

             while 1=1 do
             begin
                 len := libssh2_channel_read(channel, @buf[0], sizeof(buf));
                 if LIBSSH2_ERROR_EAGAIN = len
                    then break
                    else if(len < 0) then raise exception.create('libssh2_channel_read:'+inttostr(len));
                 if len>0 then log('libssh2_channel_read:'+inttostr(len)+' bytes');
                 wr := 0;
                 while(wr < len) do
                 begin
                     i := send(forwardsock, buf[wr], len - wr, 0);
                     if(i <= 0) then raise exception.create('write');
                     wr := wr+i;
                 end;
                 if wr>0 then log('send:'+inttostr(wr)+' bytes');
                 if libssh2_channel_eof(channel)<>0 then
                    begin
                    log('The remote client at %s:%d disconnected!',1);
                    goto shutdown;
                    end;
             end;
         end;
     shutdown:
     closesocket(forwardsock);

    if (channel<>nil) then libssh2_channel_free(channel);
    if (listener<>nil) then libssh2_channel_forward_cancel(listener);
    libssh2_session_disconnect(session, 'Client disconnecting normally');
    libssh2_session_free(session);
    log('done.',1);

end;

//direct-tcpip is what ssh -L uses,
//and forward-tcpip is what ssh -R uses.
function direct_tcpip(server_ip,username,password,remote_desthost:string;remote_destport:integer):boolean;
var
   tmp:string;
   rc,sinlen,i,sockopt :integer;
   sock,listensock,forwardsock :TSocket;
   sin:TSockAddr;
   session:PLIBSSH2_SESSION;
   fingerprint,userauthlist:pansichar;
   //listener:PLIBSSH2_LISTENER;
   channel:PLIBSSH2_CHANNEL;
   //
   fds:TFDSet;
   tv:timeval;
   len, wr:integer;
   buf:array [0..16384-1] of char;
   //

   local_listenip:string = '0.0.0.0';
   local_listenport:integer=2222;

   shost:string;
   sport:integer;
   //
   wsadata:TWSADATA;
   //
   label shutdown;
begin
    //
    rc := WSAStartup(MAKEWORD(2, 0), wsadata);
    if(rc <> 0) then raise exception.Create ('WSAStartup failed with error: '+inttostr(rc));
    //
    log('libssh2_init...',1);
    rc := libssh2_init(0);
    if(rc <> 0) then raise exception.create('libssh2 initialization failed');

    //* Connect to SSH server */
    sock := socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock = INVALID_SOCKET)  then raise exception.create('failed to open socket!');

    sin.sin_family := AF_INET;
    sin.sin_addr.s_addr := inet_addr(pchar(server_ip));
    if (INADDR_NONE = sin.sin_addr.s_addr)  then raise exception.create('inet_addr');
    sin.sin_port := htons(22);

    if (connect(sock, sin, sizeof(sockaddr_in)) <> 0) then raise exception.create('failed to connect!');

    //* Create a session instance */
    log('libssh2_session_init...');
    session := libssh2_session_init();

    if session=nil then raise exception.create ('Could not initialize SSH session!');

    //* ... start it up. This will trade welcome banners, exchange keys,
    // * and setup crypto, compression, and MAC layers
    // */
    rc := libssh2_session_handshake(session, sock);

    if (rc<>0) then raise exception.create ('Error when starting up SSH session');

    //* At this point we havn't yet authenticated.  The first thing to do
    //     * is check the hostkey's fingerprint against our known hosts Your app
    //     * may have it hard coded, may go to a file, may present it to the
    //     * user, that's your call
    //     */
        fingerprint := libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
        for i:=0 to 19 do tmp:=tmp+inttohex(ord(fingerprint[i]),2)+ ':';
        log('fingerprint:'+tmp);

    ///* check what authentication methods are available */
        userauthlist := libssh2_userauth_list(session, pchar(username), strlen(pchar(username)));

     if libssh2_userauth_password(session, pchar(username), pchar(password))<>0
                then raise exception.create ('Authentication by password failed.');
     {
     if libssh2_userauth_publickey_fromfile(session, username, keyfile1,keyfile2, password)<>0 then ;
                then raise exception.create ('Authentication by public key failed!');
     }

     listensock  := socket(PF_INET, SOCK_STREAM, IPPROTO_TCP);
     if listensock  = INVALID_SOCKET then raise exception.create ('failed to open forward socket!');

     sin.sin_family := AF_INET;
     sin.sin_port := htons(local_listenport);
     sin.sin_addr.s_addr := inet_addr(pchar(local_listenip));
     if INADDR_NONE = sin.sin_addr.s_addr then raise exception.create ('inet_addr');

    sockopt := 1;
    setsockopt(listensock, SOL_SOCKET, SO_REUSEADDR, sockopt,sizeof(sockopt));
    sinlen := sizeof(sin);
    if -1 = bind(listensock, sin, sinlen) then raise exception.create('bind');

    if -1 = listen(listensock, 2) then raise exception.create('listen');

    log('Waiting for TCP connection on ...'+ inet_ntoa(sin.sin_addr) +':' + inttostr( ntohs(sin.sin_port)));

    forwardsock := accept(listensock, @sin, sinlen);
    if forwardsock = INVALID_SOCKET then raise exception.create('failed to accept forward socket!');

    shost := inet_ntoa(sin.sin_addr);
    sport := ntohs(sin.sin_port);

    log('Forwarding connection from here to remote '+ shost+':'+inttostr(sport)+' '+ remote_desthost+':'+inttostr(remote_destport));

    channel := libssh2_channel_direct_tcpip_ex(session, pchar(remote_desthost),remote_destport, pchar(shost), sport);

    if channel=nil then raise exception.create('Could not open the direct-tcpip channel!'
                              +#13#10+'(Note that this can be a problem at the server!'
                              +#13#10+'Please review the server logs.)');

    //* Must use non-blocking IO hereafter due to the current libssh2 API */
    libssh2_session_set_blocking(session, 0);

     while 1=1 do
       begin
             FD_ZERO(fds);
             FD_SET(forwardsock, fds);
             tv.tv_sec := 0;
             tv.tv_usec := 100000;
             rc := select(forwardsock + 1, @fds, nil, nil, @tv);
             if -1 = rc then
                begin
                log('select');
                goto shutdown;
                end;

             if (rc<>0) and (FD_ISSET(forwardsock, fds)) then
             begin
                 len := recv(forwardsock, @buf[0], sizeof(buf), 0);
                 if(len < 0)
                        then raise exception.create('read')
                        else if (0 = len) then
                        begin
                        log('The client disconnected! '+shost+':'+inttostr(sport),1);
                        goto shutdown;
                        end;
                 if len>0 then log('recv:'+inttostr(len)+' bytes');
                 wr := 0;
                 while wr<len do
                   begin
                     i := libssh2_channel_write(channel, @buf[wr], len-wr);
                     if i>0 then log('libssh2_channel_write:'+inttostr(i)+' bytes');
                     if i=len then break; //buffer has been sent
                     if(i < 0) then
                          begin
                          log('libssh2_channel_write: '+inttostr(i));
                          //goto shutdown;
                          break;
                          end;
                     wr := wr+i;
                   end;

             end; //if (rc<>0) and (FD_ISSET(forwardsock, fds)) then

             while 1=1 do
             begin
                 len := libssh2_channel_read(channel, @buf[0], sizeof(buf));
                 if LIBSSH2_ERROR_EAGAIN = len
                    then break
                    else if(len < 0) then raise exception.create('libssh2_channel_read:'+inttostr(len));
                 if len>0 then log('libssh2_channel_read:'+inttostr(len)+' bytes');
                 wr := 0;
                 while(wr < len) do
                 begin
                     i := send(forwardsock, buf[wr], len - wr, 0);
                     if(i <= 0) then raise exception.create('write');
                     wr := wr+i;
                 end;
                 if wr>0 then log('send:'+inttostr(wr)+' bytes');
                 if libssh2_channel_eof(channel)<>0 then
                    begin
                    log('The remote client at disconnected!',1);
                    goto shutdown;
                    end;
             end;
         end;
     shutdown:
     closesocket(forwardsock);
     closesocket(listensock);

    if (channel<>nil) then libssh2_channel_free(channel);

    libssh2_session_disconnect(session, 'Client disconnecting normally');
    libssh2_session_free(session);
    libssh2_exit();
    log('done.',1);

end;


procedure execpty(channel_:PLIBSSH2_CHANNEL;command_:string);
var
   buffer:array[0..8192-1] of char;
   buflen,i:integer;
   commands:TArrayStr ;
begin
log('libssh2_channel_request_pty...');
//vt100, vt102, vt220, and xterm -- vanilla
if libssh2_channel_request_pty(channel_, 'vanilla')<>0 then
   begin
   log('Cannot obtain pty',1);
   exit;
   end;
//libssh2_channel_request_pty_size(channel, 80, 24);
//* Open a SHELL on that pty */
log('libssh2_channel_shell...');
if libssh2_channel_shell(channel_)<>0 then
   begin
   log('Cannot open shell',1);
   exit;
   end;
libssh2_channel_set_blocking(channel_,0);
//the banner...
while 1=1 do
    begin
    buflen:=libssh2_channel_read(channel_,@buffer[0],length(buffer));
    if buflen>0 then write(copy(buffer,0,buflen));
    if buflen<=0 then break;
    end;
sleep(delay);
//
commands:=SplitString(command_,';');
for i:=0 to length(commands) -1 do
  begin
    if commands[i]<>'' then
    begin
    buflen:=libssh2_channel_write(channel_,pchar(commands[i]+#13#10),length(commands[i]+#13#10));
    //writeln(buflen);
    sleep(delay);
    while 1=1 do
        begin
        buflen:=libssh2_channel_read(channel_,@buffer[0],length(buffer));
        //writeln(buflen);
        if buflen>0 then write(copy(buffer,0,buflen));
        if buflen<=0 then break;
        end;//while
    //sleep(delay);
  end;//if commands[i]<>'' then
  end;//for i:=0 to length(commands) -1 do
end;

procedure exec(channel_:PLIBSSH2_CHANNEL;command_:string);
var
   buffer:array[0..8192-1] of char;
   buflen:integer;
begin
//libssh2_channel_set_blocking(channel,0);
log('libssh2_channel_exec...');
if libssh2_channel_exec(channel_ ,pchar(command_))<>0 then log('cannot libssh2_channel_exec',1)
else
begin
  while 1=1 do
  begin
  buflen:=libssh2_channel_read(channel_,@buffer[0],length(buffer));
  //writeln(buflen);
  if buflen>0 then write(copy(buffer,0,buflen)); // else log('no output',1);
  if buflen<=0 then break;
  end;//while
end;//if libssh2_channel_exec
end;

procedure shell(channel_:PLIBSSH2_CHANNEL);
var
   s:string;
   ReadThread:TReadThread;
begin
{/* Request a terminal with 'vanilla' terminal emulation
* See /etc/termcap for more options
*/}
log('libssh2_channel_request_pty...');
//vt100, vt102, vt220, and xterm -- vanilla
if libssh2_channel_request_pty(channel_, 'vanilla')<>0 then
   begin
   log('Cannot obtain pty',1);
   exit;
   end;
//libssh2_channel_request_pty_size(channel, 80, 24);
//* Open a SHELL on that pty */
log('libssh2_channel_shell...');
if libssh2_channel_shell(channel_)<>0 then
   begin
   log('Cannot open shell',1);
   exit;
   end;
ReadThread:=TReadThread.Create(channel_);
ReadThread.Resume;
while true do
   begin
   readln(s);
   if s='exit' then break;
   ssend:=s+LineEnding;
   bNewString:=true;
   end;
ReadThread.Terminate;
end;

function init_session(sock:tsocket):PLIBSSH2_SESSION;
var
fingerprint,userauthlist:PAnsiChar;
tmp:string;
i:integer;
begin
log('libssh2_init...');
    if libssh2_init(0)<>0 then
      begin
      log('Cannot libssh2_init',1);
      exit;
      end;
    { /* Create a session instance and start it up. This will trade welcome
         * banners, exchange keys, and setup crypto, compression, and MAC layers
         */
         }
    log('libssh2_session_init...');
    result := libssh2_session_init();

    //* tell libssh2 we want it all done non-blocking */
    //libssh2_session_set_blocking(result, 0);

    //log('libssh2_session_startup...');
    //if libssh2_session_startup(session, bsock.Socket)<>0 then
    {
    if libssh2_session_startup(result, sock)<>0 then
      begin
      log('Cannot establishing SSH session',1);
      exit;
      end;
    }
    //latest libssh2 version instead of libssh2_session_startup
    log('libssh2_session_handshake...');
    if libssh2_session_handshake(result, sock)<>0 then
      begin
      writeln('Cannot libssh2_session_handshake');
      exit;
      end;

    //
    //writeln(libssh2_trace(session,LIBSSH2_TRACE_ERROR or LIBSSH2_TRACE_CONN or LIBSSH2_TRACE_TRANS or LIBSSH2_TRACE_SOCKET));
    log('libssh2_version:'+libssh2_version(0));
    //
    {
    /* At this point we havn't authenticated. The first thing to do is check
     * the hostkey's fingerprint against our known hosts Your app may have it
     * hard coded, may go to a file, may present it to the user, that's your
     * call
     */
    }
    //not needed if you dont care about known hosts
    log('libssh2_hostkey_hash...');
    fingerprint := libssh2_hostkey_hash(result, LIBSSH2_HOSTKEY_HASH_SHA1);
    if fingerprint=nil then begin log('no fingerpint',1);exit;end;
    log('Host fingerprint ');
    i:=0;
    //while fingerprint[i]<>#0 do
    for i:=0 to 19 do
      begin
      tmp:=tmp+inttohex(ord(fingerprint[i]),2)+ ':';
      //i:=i+1;
      end;
    log(tmp);
    log('Assuming known host...');
end;

procedure scp;
var
sock:tsocket;
session:PLIBSSH2_SESSION=nil;
channel:PLIBSSH2_CHANNEL=nil;
userauthlist:PAnsiChar;
hfile:thandle=thandle(-1);
fsize:int64=0;
size:dword=0;
i:integer;
mem:array [0..1023] of char;
errmsg:pchar;
begin

//
try
  if init_socket(sock)=false then begin writeln('socket failed');exit;end; ;
  except
  on e:exception do
     begin
     writeln(e.Message );
     exit;
     end;
  end;

  //
  session:=init_session(sock);
  if session=nil then
    begin
    log('session is null');
    exit;
    end;

  //libssh2_trace(session, 0); //TRACE_LIBSSH2 //only if build in debug mode...

  //optional : only to check auth methods
  log('libssh2_userauth_list...');
  userauthlist := libssh2_userauth_list(session, pchar(username), strlen(pchar(username)));
  log(strpas(userauthlist));

  //
  log('libssh2_userauth_password...');
  if libssh2_userauth_password(session, pchar(username), pchar(password))<>0 then
    begin
    log('Authentication by password failed',1);
    exit;
    end;
  log('Authentication succeeded');



  //
  log('local_filename:'+local_filename);
  hfile := CreateFile(pchar(local_filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
  if hfile=thandle(-1) then begin log('invalid handle',1);exit;end;
  Int64Rec(fsize).Lo := GetFileSize(hfile, @Int64Rec(fsize).Hi);
  log('size:'+inttostr(fsize));
  //* Send a file via scp. The mode parameter must only have permissions! */
  log('remote_filename:'+remote_filename);
  channel := libssh2_scp_send(session, pansichar(remote_filename), integer(0777),size_t(fsize));

  if not assigned(channel) then
    begin
    libssh2_session_last_error(session, errmsg, i, 0);
    log(strpas(errmsg));
    log('Cannot open channel',1);
    exit;
    end;

  while 1=1 do
        begin
        ReadFile (hfile,mem[0],sizeof(mem),size,nil);
        if size<=0 then break;
        //* write the same data over and over, until error or completion */
        i:= libssh2_channel_write(channel, @mem[0], size);
        if (i<>size) then begin log('libssh2_channel_write error',1);break;end;
        log('libssh2_sftp_write:'+inttostr(i)+' bytes');

        end; //while 1=1 do
      closehandle(hfile);

//
log('Sending EOF');
libssh2_channel_send_eof(channel);
log('Waiting for EOF');
libssh2_channel_wait_eof(channel);
log('Waiting for channel to close');
libssh2_channel_wait_closed(channel);
libssh2_channel_free(channel);

    if (session<>nil) then
      begin
      libssh2_session_disconnect(session, 'Normal Shutdown');
      libssh2_session_free(session);
      end;

    closesocket(sock);
    libssh2_exit();


end;

procedure main;
var
   channel:PLIBSSH2_CHANNEL;
   session:PLIBSSH2_SESSION;
   userauthlist:PAnsiChar;
   i:integer;
   //
   sock:tsocket;
begin
  try
  if init_socket(sock)=false then begin writeln('socket failed');exit;end; ;
  except
  on e:exception do
     begin
     writeln(e.Message );
     exit;
     end;
  end;
  //
  if 1=1 then
    begin

    session:=init_session(sock);


    //
    //optional : only to check auth methods
    log('libssh2_userauth_list...');
    userauthlist := libssh2_userauth_list(session, pchar(username), strlen(pchar(username)));
    log(strpas(userauthlist));
    //
    if ((privatekey='') and (publickey='')) and (password='') then
      begin
      writeln('Password for ', host,' : ');
      readln(password);
      end;
    if ((privatekey='') and (publickey='')) and (password<>'') then
    begin
    log('libssh2_userauth_password...');
    if libssh2_userauth_password(session, pchar(username), pchar(password))<>0 then
      begin
      log('Authentication by password failed',1);
      exit;
      end;
    log('Authentication succeeded');
    end;
    if (privatekey<>'') or (publickey<>'') then
    begin
    log('libssh2_userauth_publickey_fromfile');
    //you need the private key on your client and the public key to be added to .ssh/authorized_keys on the server
    //public key can be derived from private key so public key can be skipped (good for security...)
    //not relevant here but chmod 0700 id_rsa on a linux ssh client
    //not relevant but from a ssh linux client you can do:
    //cat ~/.ssh/id_rsa.pub | ssh user@server 'cat >> .ssh/authorized_keys'
    log('private key:'+privatekey );
    log('public key:'+publickey  );
    if (privatekey<>'') and (publickey='') then
        i:= libssh2_userauth_publickey_fromfile(session, pchar(username), nil{pchar(publickey)},pchar(privatekey),nil);
    if (publickey<>'') and (privatekey='') then
        i:= libssh2_userauth_publickey_fromfile(session, pchar(username), pchar(publickey),nil{pchar(privatekey)},nil);
    if (publickey<>'') and (privatekey<>'') then
        i:= libssh2_userauth_publickey_fromfile(session, pchar(username), pchar(publickey),pchar(privatekey),nil);
    if i<>0 then
      begin
      log('libssh2_userauth_publickey_fromfile failed:'+inttostr(i),1);
      exit;
      end;
    end; //if not FileExists (password) then
    log('libssh2_channel_open_session...');
    //* Request a shell */
    channel := libssh2_channel_open_session(session);
    if not assigned(channel) then
      begin
      log('Cannot open channel',1);
      exit;
      end;
    //shell mode
    if command='' then shell(channel);
    //exec mode
    if command<>'' then
    begin
      if pty<>'true' then exec(channel,command);
      if pty='true' then execpty(channel,command);
    end;//if command<>'' then
    //
    libssh2_channel_free(channel);
    libssh2_session_disconnect(session,'bye');
    libssh2_session_free(session);
    closesocket(sock);
    log('done.');
    end
  else
    log('Cannot connect',1);
end;

begin




  cmd := TCommandLineReader.create;
  cmd.declareString('ip', '192.168.1.254');
  cmd.declareInt('port', '22',22);
  cmd.declareString('username', 'mandatory');
  cmd.declareString('password', 'password');
  cmd.declareString('privatekey', 'path to a privatekey file');
  cmd.declareString('publickey', 'path to a publickey file, not needed if you have the privatekey');
  cmd.declareString('command', 'optional, if none enter shell mode');
  cmd.declareString('pty', 'true|false, default=true is no command provided');
  cmd.declareString('debug', 'true|false','false');
  cmd.declareInt ('delay', 'delay between 2 read/write in command+pty mode',1000);
  cmd.declareflag('reverse', 'reverse forwarding');
  cmd.declareflag('local', 'local forwarding');
  cmd.declareflag('scp', 'scp');
  cmd.declareflag('genkey', 'generate rsa keys public.pem and private.pem');
  cmd.declareflag('mkcert', 'make a self sign root cert');
  cmd.declareString('destip', 'forward mode (local or reverse)');
  cmd.declareint('destport', 'forward mode (local or reverse');
  //
  cmd.declareString('local_filename', 'local filename');
  cmd.declareString('remote_filename', 'remote filename');
  cmd.parse(cmdline);

  debug:= cmd.readString('debug')='true';

  if cmd.existsProperty('genkey')=true then
    begin
    try
    LoadSSL;
    if generate_key=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('mkcert')=true then
    begin
    try
    LoadSSL;
    if mkcert=true then writeln('ok') else writeln('not ok');
    finally
    FreeSSL;
    end;
    exit;
    end;

  if cmd.existsProperty('ip')=false then
    begin
    writeln('Usage: ssh --help');
    exit;
    end;

  host:=cmd.readString('ip');
  port:=cmd.readint('port');
  username:=cmd.readString('username');
  password:=cmd.readString('password');
  privatekey:=cmd.readString('privatekey');
  publickey:=cmd.readString('publickey');
  command:=cmd.readString('command');
  local_filename:=cmd.readString('local_filename');
  remote_filename:=cmd.readString('remote_filename');
  pty:=cmd.readString('pty');
  delay:=cmd.readInt ('delay');

  if cmd.existsProperty ('scp') then
    begin
    scp;
    exit;
    end;

  if cmd.existsProperty ('reverse') then
     begin
     //remote ssh server will listen on port 2222 and forward traffic from localhost:2222 to remotehost:remoteport
     //forward_tcpip ('192.168.1.129','jeedom','Mjeedom96','www.google.com',80);
     forward_tcpip (host,username,password,cmd.readString('destip'),cmd.readint('destport'));
     exit;
     end;

  if cmd.existsProperty ('local') then
     begin
     //local host will list on port 2222 and forward traffic from localhost:2222 to remotehost:remoteport via ssh server
     //forward_tcpip ('192.168.1.129','jeedom','Mjeedom96','www.google.com',80);
     direct_tcpip (host,username,password,cmd.readString('destip'),cmd.readint('destport'));
     exit;
     end;



 //
  main;
end.


