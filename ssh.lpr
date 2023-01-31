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
  rcmdline in '..\rcmdline-master\rcmdline.pas';

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
  host,username,password,command,pty,privatekey:string;
  port:integer=22;
  //
  cmd: TCommandLineReader;


  procedure log(msg:string;level:byte=0);
begin
  if (level=0) and (debug=false) then exit;
  writeln(msg);
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
//also check allowtcpforwarding ?
//sudo netstat -ap | grep :<port_number>
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
    log('libssh2_session_startup...,1');
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

procedure main;
var
   channel:PLIBSSH2_CHANNEL;
   session:PLIBSSH2_SESSION;
   fingerprint,userauthlist:PAnsiChar;
   tmp:string;
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
    session := libssh2_session_init();

    //* tell libssh2 we want it all done non-blocking */
    //libssh2_session_set_blocking(session, 0);

    log('libssh2_session_startup...');
    //if libssh2_session_startup(session, bsock.Socket)<>0 then
    if libssh2_session_startup(session, sock)<>0 then
      begin
      log('Cannot establishing SSH session',1);
      exit;
      end;

    //latest libssh2 version instead of libssh2_session_startup
    {
    if libssh2_session_handshake(session, sock.socket)<>0 then
      begin
      writeln('Cannot libssh2_session_handshake');
      exit;
      end;
    }
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
    fingerprint := libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
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
    //
    //optional : only to check auth methods
    log('libssh2_userauth_list...');
    userauthlist := libssh2_userauth_list(session, pchar(username), strlen(pchar(username)));
    log(strpas(userauthlist));
    //
    if password='' then
      begin
      writeln('Password for ', host,' : ');
      readln(password);
      end;
    if not FileExists (password) then
    begin
    log('libssh2_userauth_password...');
    if libssh2_userauth_password(session, pchar(username), pchar(password))<>0 then
      begin
      log('Authentication by password failed',1);
      exit;
      end;
    log('Authentication succeeded');
    end
    else //if not FileExists (password) then
    begin
    privatekey:=password;
    log('libssh2_userauth_publickey_fromfile');
    //you need the private key on your client and the public key to be added to .ssh/authorized_keys on the server
    //public key can be derived from private key so public key can be skipped (good for security...)
    //not relevant here but chmod 0700 id_rsa on a linux ssh client
    //not relevant but from a ssh linux client you can do:
    //cat ~/.ssh/id_rsa.pub | ssh user@server 'cat >> .ssh/authorized_keys'
    i:= libssh2_userauth_publickey_fromfile(session, pchar(username), nil{pchar(GetCurrentDir + '\id_rsa.pub')},pchar(privatekey),nil);
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
      log('Cannot open session',1);
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
  cmd.declareString('password', 'password or path to a pub key file, prompted if empty');
  cmd.declareString('command', 'optional, if none enter shell mode');
  cmd.declareString('pty', 'true|false, default=true is no command provided');
  cmd.declareString('debug', 'true|false','false');
  cmd.declareInt ('delay', 'delay between 2 read/write in command+pty mode',1000);
  cmd.declareflag('reverse', 'reverse forwarding');
  cmd.declareString('destip', 'forward mode','127.0.0.1');
  cmd.declareint('destport', 'forward mode',80);
  cmd.parse(cmdline);

  if cmd.existsProperty('ip')=false then
    begin
    writeln('Usage: ssh --help');
    exit;
    end;

  host:=cmd.readString('ip');
  port:=cmd.readint('port');
  username:=cmd.readString('username');
  password:=cmd.readString('password');
  command:=cmd.readString('command');
  pty:=cmd.readString('pty');
  debug:= cmd.readString('debug')='true';
  delay:=cmd.readInt ('delay');



  if cmd.existsProperty ('reverse') then
     begin
     //forward_tcpip ('192.168.1.129','jeedom','Mjeedom96','127.0.0.1',80);
     forward_tcpip (host,username,password,cmd.readString('destip'),cmd.readint('destport'));
     exit;
     end;


 //
  main;
end.


