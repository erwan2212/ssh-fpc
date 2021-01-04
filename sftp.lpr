program sftp;

//libssh2 available here  https://windows.php.net/downloads/pecl/releases/ssh2/
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
  libssh2,libssh2_sftp,
  winsock2;

var
  debug:boolean=false;
  session:PLIBSSH2_SESSION;
  fingerprint,userauthlist:PAnsiChar;
  tmp,s,ssend:string;
  channel:PLIBSSH2_CHANNEL;
  sftp_session:PLIBSSH2_SFTP;
  sftp_handle:PLIBSSH2_SFTP_HANDLE;
  i:integer;
  bNewString:boolean;
  //
  buffer:array[0..10000] of char;
  buflen:integer;
  //
  host,username,password,verb,path:string;
  //
  mem:array [0..1023] of char;
  longentry:array [0..511] of char;
  attrs:LIBSSH2_SFTP_ATTRIBUTES;
  //
  hfile:thandle;
  size:dword;
  //
  sock:tsocket;

procedure log(msg:string;level:byte=0);
begin
  if (level=0) and (debug=false) then exit;
  writeln(msg);
end;

function UnixToDateTime(USec: Longint): TDateTime;
  const
  UnixStartDate: TDateTime = 25569.0; // 01/01/1970
begin
  Result := (Usec / 86400) + UnixStartDate;
end;

function DateTimeToUnix(dtDate: TDateTime): Longint;
const
UnixStartDate: TDateTime = 25569.0; // 01/01/1970
begin
  Result := Round((dtDate - UnixStartDate) * 86400);
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
    writeln('Usage: ',paramstr(0),' ip username password verb path [source]');
    exit;
    end;
  host:=paramstr(1);
  username:=paramstr(2);
  password:=paramstr(3);
  verb:=paramstr(4);
  path:=paramstr(5);
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

  if 1=1 then begin
    log('libssh2_init...');
    if libssh2_init(0)<>0 then
      begin
      writeln('Cannot libssh2_init');
      exit;
      end;
    //* Create a session instance and start it up. This will trade welcome
    //* banners, exchange keys, and setup crypto, compression, and MAC layers
    log('libssh2_session_init...');
    session := libssh2_session_init();

    //* tell libssh2 we want it all done non-blocking */
    //libssh2_session_set_blocking(session, 0);

    log('libssh2_session_startup...');
    if libssh2_session_startup(session, sock)<>0 then
      begin
      log('Cannot establishing SSH session',1);
      exit;
      end;

    //
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
    log('libssh2_hostkey_hash...');
    fingerprint := libssh2_hostkey_hash(session, LIBSSH2_HOSTKEY_HASH_SHA1);
    if fingerprint=nil then begin log('no fingerpint',1);exit;end;
    log('Host fingerprint ');
    i:=0;
    //while fingerprint[i]<>#0 do
    for i:=0 to 19 do
      begin
      tmp:=tmp+inttohex(ord(fingerprint[i]),2)+':';
      //i:=i+1;
      end;
    log(tmp);
    log('Assuming known host...');
    //
    log('libssh2_userauth_list...');
    userauthlist := libssh2_userauth_list(session, pchar(username), strlen(pchar(username)));
    log(strpas(userauthlist));
    //
    if paramstr(3)='' then
      begin
      write('Password for ', host,' : ');
      readln(password);
      end
      else password:=paramstr(3);
    log('libssh2_userauth_password...');
    if libssh2_userauth_password(session, pchar(username), pchar(password))<>0 then
      begin
      log('Authentication by password failed',1);
      exit;
      end;
    log('Authentication succeeded');

    log('libssh2_sftp_init...');
    sftp_session := libssh2_sftp_init(session);
    if sftp_session=nil then
      begin
      log('cannot libssh2_sftp_init',1);
      exit;
      end;

    //* Since we have not set non-blocking, tell libssh2 we are blocking */
     libssh2_session_set_blocking(session, 1);

    //
    if verb='rmdir' then
    begin
    //* Make a directory via SFTP */
    log('libssh2_sftp_rmdir');
    i := libssh2_sftp_rmdir(sftp_session, pchar(path));
    end;
    //
    if verb='mkdir' then
    begin
    //* Make a directory via SFTP */
    log('libssh2_sftp_mkdir');
    i := libssh2_sftp_mkdir(sftp_session, pchar(path),
                            LIBSSH2_SFTP_S_IRWXU or
                            LIBSSH2_SFTP_S_IRGRP or LIBSSH2_SFTP_S_IXGRP or
                            LIBSSH2_SFTP_S_IROTH or LIBSSH2_SFTP_S_IXOTH);
    end;
    //
    if verb='put' then
    begin
    //* Request a file via SFTP */
    log('libssh2_sftp_open');
    sftp_handle :=libssh2_sftp_open(sftp_session, pchar(path), LIBSSH2_FXF_WRITE or LIBSSH2_FXF_CREAT or LIBSSH2_FXF_TRUNC,
                          LIBSSH2_SFTP_S_IRUSR or LIBSSH2_SFTP_S_IWUSR or
                          LIBSSH2_SFTP_S_IRGRP or LIBSSH2_SFTP_S_IROTH);
    if sftp_handle=nil then
          begin
          log('cannot libssh2_sftp_open',1);
          exit;
          end;
    hfile := CreateFile(pchar(paramstr(6)), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
    if hfile=thandle(-1) then begin log('invalid handle');exit;end;
    while 1=1 do
      begin
      ReadFile (hfile,mem[0],sizeof(mem),size,nil);
      if size<=0 then break;
      i := libssh2_sftp_write(sftp_handle, @mem[0], size);
      if (i<>size) then begin log('libssh2_sftp_write error',1);break;end;
      end; //while 1=1 do
    closehandle(hfile);
    libssh2_sftp_close(sftp_handle);
    end;
    // if verb='put' then
    if verb='get' then
    begin
    //* Request a file via SFTP */
    log('libssh2_sftp_open');
    sftp_handle :=libssh2_sftp_open(sftp_session, pchar(path), LIBSSH2_FXF_READ, 0);
    if sftp_handle=nil then
          begin
          log('cannot libssh2_sftp_open',1);
          exit;
          end;
    hfile := CreateFile(pchar(ExtractFileName (path)), GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, nil, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, 0);
    if hfile=thandle(-1) then begin log('invalid handle');exit;end;
    while 1=1 do
      begin
       i := libssh2_sftp_read(sftp_handle, @mem[0], sizeof(mem));
       if i>0 then
         begin
         //log(strpas(@mem[0]),1);
         WriteFile(hfile, mem[0], i, size, nil);
         end
         else break;
      end; //while 1=1 do
    closehandle(hfile);
    libssh2_sftp_close(sftp_handle);
    end;
    // if verb='get' then
    if verb='dir' then
    begin
    log('libssh2_sftp_opendir');
    sftp_handle := libssh2_sftp_opendir(sftp_session, pchar(path));
    if sftp_handle=nil then
          begin
          log('cannot libssh2_sftp_opendir',1);
          exit;
          end;
    while 1=1 do
      begin
       i := libssh2_sftp_readdir_ex(sftp_handle, @mem[0], sizeof(mem),longentry, sizeof(longentry), @attrs);
       if i>0 then
         begin
         //log(strpas(@mem[0])+#9+inttostr(attrs^.filesize),1);
         if (attrs.flags and LIBSSH2_SFTP_ATTR_SIZE)=LIBSSH2_SFTP_ATTR_SIZE
            then tmp:=inttostr(attrs.filesize ) else tmp:='';
         log(strpas(@mem[0])+#9+tmp+#9+DateTimeToStr (UnixToDateTime (attrs.mtime )),1);
         end
         else break;
      end; //while 1=1 do
    libssh2_sftp_closedir(sftp_handle);
    end; //if verb='dir' then
    //
    libssh2_sftp_shutdown(sftp_session);
    //
    libssh2_session_disconnect(session, 'bye');
    libssh2_session_free(session);
    //
    closesocket(sock);
    end //if 1=1
  else
    log('Cannot connect',1);
   libssh2_exit();
end.



