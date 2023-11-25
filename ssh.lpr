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
  rcmdline in '..\rcmdline-master\rcmdline.pas',
  utils;



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

  bNewString:boolean;
  ssend,encrypted:string;
  delay:integer;
  //
  host,username,password,command,pty,privatekey,publickey,cert,filename,remote_filename:string;
  port:integer=22;
  //
  hfile_:thandle=thandle(-1);
  mem_:array[0..8192-1] of char;
  size_:dword=0;
  //
  cmd: TCommandLineReader;


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
HostEnt:PHostEnt;
begin
  result:=false;
  //
  err := WSAStartup(MAKEWORD(2, 0), wsadata);
  if(err <> 0) then raise exception.Create ('WSAStartup failed with error: '+inttostr(err));
  //
  hostaddr := inet_addr(pchar(host));
  //not an ip? lets try to resolve hostname
  if hostaddr = INADDR_NONE then
    begin
    HostEnt:=gethostbyname(pchar(host));
    if HostEnt <> nil then hostaddr:=Integer(Pointer(HostEnt^.h_addr^)^);
    end;
  //  
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
    //channel := libssh2_channel_direct_tcpip(session, pchar(remote_desthost),remote_destport);

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

{
const int _O_RDONLY = 0x0000;  /* open for reading only */
const int _O_WRONLY = 0x0001;  /* open for writing only */
const int _O_RDWR   = 0x0002;  /* open for reading and writing */
const int _O_APPEND = 0x0008;  /* writes done at eof */

const int _O_CREAT  = 0x0100;  /* create and open file */
const int _O_TRUNC  = 0x0200;  /* open and truncate */
const int _O_EXCL   = 0x0400;  /* open only if file doesn't already exist */

}

function scp_write(local,remote:string):boolean;
var
sock:tsocket;
session:PLIBSSH2_SESSION=nil;
channel:PLIBSSH2_CHANNEL=nil;
userauthlist:PAnsiChar;
hfile:thandle=thandle(-1);
fsize:int64=0;
size:dword=0;
i:integer;
mem:array [0..8192-1] of char;
errmsg:pchar;
mode:integer;
begin
log('scp_write');
result:=false;
//
try
  if init_socket(sock)=false then begin writeln('socket failed');exit;end; ;
  except
  on e:exception do
     begin
     log(e.Message,1 );
     exit;
     end;
  end;
  //mode:=1;
  //ioctlsocket (sock, FIONBIO, @mode);
  //
  session:=init_session(sock);
  if session=nil then
    begin
    log('session is null',1);
    exit;
    end;

  //libssh2_trace(session, 0); //TRACE_LIBSSH2 //only if build in debug mode...

  //optional : only to check auth methods
  log('libssh2_userauth_list...');
  userauthlist := libssh2_userauth_list(session, pchar(username), strlen(pchar(username)));
  log(strpas(userauthlist));

  //
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
  //
  log('local_filename:'+local);
  hfile := CreateFile(pchar(local), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
  if hfile=thandle(-1) then begin log('invalid handle',1);exit;end;
  Int64Rec(fsize).Lo := GetFileSize(hfile, @Int64Rec(fsize).Hi);
  log('size:'+inttostr(fsize));
  //* Send a file via scp. The mode parameter must only have permissions! */
  log('remote_filename:'+remote);
  //channel := libssh2_scp_send(session, pansichar(remote_filename), integer(0777),size_t(fsize));
  //libssh2_session_set_blocking(session, 1);
  channel :=libssh2_scp_send64(session,pansichar(remote), $102,size_t(fsize),0,0);

  if not assigned(channel) then
    begin
    libssh2_session_last_error(session, errmsg, i, 0);
    log('error:'+strpas(errmsg));
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

result:=true;
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
  debug:=true;



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
  //
  cmd.declareflag('reverse', 'reverse forwarding');
  cmd.declareflag('local', 'local forwarding');
  cmd.declareString('destip', 'forward mode (local or reverse)');
  cmd.declareint('destport', 'forward mode (local or reverse');
  //
  cmd.declareflag('put', 'secure copy a file to a remote ssh host');
  cmd.declareString('filename', 'local filename');
  cmd.declareString('remote_filename', 'remote filename');
  //
  cmd.parse(cmdline);

  debug:= cmd.readString('debug')='true';

  if cmd.existsProperty('ip')=false then
    begin
    writeln('https://github.com/erwan2212');
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
  filename:=cmd.readString('filename');
  remote_filename:=cmd.readString('remote_filename');
  pty:=cmd.readString('pty');
  delay:=cmd.readInt ('delay');

  if cmd.existsProperty ('put') then
    begin
    if remote_filename='' then remote_filename :=extractfilename(filename);
    if scp_write(filename,remote_filename)=true
       then log('ok',1)
       else log('not ok',1);
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


