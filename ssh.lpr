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
  //blcksock,  //was using synapse before...
  winsock2;

type

  { TMyThread }

  TReadThread=class(TThread)
    private
      FChannel:PLIBSSH2_CHANNEL;
    protected
      procedure Execute; override;
    public
      constructor Create(channel:PLIBSSH2_CHANNEL);
    end;

var
  debug:boolean=false;
  //bsock:TTCPBlockSocket;
  session:PLIBSSH2_SESSION;
  fingerprint,userauthlist:PAnsiChar;
  tmp,s,ssend:string;
  channel:PLIBSSH2_CHANNEL;
  i:integer;
  ReadThread:TReadThread;
  bNewString:boolean;
  //
  buffer:array[0..10000] of char;
  buflen:integer;
  //
  host,username,password,command,privatekey:string;
  //
  sock:tsocket;

  procedure log(msg:string;level:byte=0);
begin
  if (level=0) and (debug=false) then exit;
  writeln(msg);
end;

{ TReadThread }

procedure TReadThread.Execute;
var
  buf:array[0..10000] of char;
  len:integer;
begin
  libssh2_channel_set_blocking(channel,0);
  while not Terminated do
    begin
    len:=libssh2_channel_read(channel,buf,10000);
    if len>0 then
      begin
      write(copy(buf,1,len));
      end
    else if bNewString then
      begin
      libssh2_channel_write(channel,pchar(ssend),length(ssend));
      bNewString:=false;
      end
    else
      sleep(1000);
    end;
end;

constructor TReadThread.Create(channel: PLIBSSH2_CHANNEL);
begin
  inherited Create(true);
  FChannel:=channel;
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
  sin.sin_port := htons(22);
  sin.sin_addr.s_addr := hostaddr;
  if connect(sock_, tsockaddr(sin), sizeof(sockaddr_in)) <> 0
     then raise exception.Create ('failed to connect');
  //
  result:=true;

end;

begin
  if Paramcount<2 then
    begin
    writeln('Usage: ',paramstr(0),' ip username password [command]',1);
    exit;
    end;
  host:=paramstr(1);
  username:=paramstr(2);
  {
  bsock := TTCPBlockSocket.Create;
  bsock.Connect(host,'22');
  if bsock.LastError=0 then
  }
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
    if paramstr(3)='' then
      begin
      writeln('Password for ', host,' : ');
      readln(password);
      end
      else password:=paramstr(3);
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
    if paramstr(4)='' then
    begin
    {/* Request a terminal with 'vanilla' terminal emulation
             * See /etc/termcap for more options
             */}
        log('libssh2_channel_request_pty...');
        if libssh2_channel_request_pty(channel, 'vanilla')<>0 then
          begin
          log('Cannot obtain pty',1);
          exit;
          end;
        //* Open a SHELL on that pty */
        log('libssh2_channel_shell...');
        if libssh2_channel_shell(channel)<>0 then
          begin
          log('Cannot open shell',1);
          exit;
          end;
    ReadThread:=TReadThread.Create(channel);
    ReadThread.Resume;
    while true do
      begin
      readln(s);
      if s='exit' then
        break;
      ssend:=s+LineEnding;
      bNewString:=true;
      end;
    ReadThread.Terminate;
    end;
    //exec mode
    if paramstr(4)<>'' then
    begin
    //libssh2_channel_set_blocking(channel,0);
    command:=paramstr(4);
    log('libssh2_channel_exec...');
    if libssh2_channel_exec(channel ,pchar(command))<>0
       then log('cannot libssh2_channel_exec',1)
       else
       begin
       buflen:=libssh2_channel_read(channel,buffer,10000);
       if buflen>0 then write(copy(buffer,1,buflen)) else log('no output',1);
       end;
    end;
    //
    libssh2_channel_free(channel);
    libssh2_session_disconnect(session,'bye');
    libssh2_session_free(session);
    //bsock.Free;
    closesocket(sock);
    end
  else
    log('Cannot connect',1);
end.


