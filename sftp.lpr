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
  winsock2,
  rcmdline in '..\rcmdline-master\rcmdline.pas';

var
  debug:boolean=false;
  session:PLIBSSH2_SESSION;
  sftp_session:PLIBSSH2_SFTP;
  sftp_handle:PLIBSSH2_SFTP_HANDLE;
  fingerprint,userauthlist:PAnsiChar;
  tmp,s:string;
  i:integer;
  //
  host,username,password,privatekey,verb,path,local_filename,dest_filename:string;
  port:integer=22;
  //
  mem:array [0..1023] of char;
  longentry:array [0..511] of char;
  attrs:LIBSSH2_SFTP_ATTRIBUTES;
  //
  hfile:thandle;
  size:dword;
  //
  sock:tsocket;
  //
  cmd: TCommandLineReader;

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
  sin.sin_port := htons(port);
  sin.sin_addr.s_addr := hostaddr;
  if connect(sock_, tsockaddr(sin), sizeof(sockaddr_in)) <> 0
     then raise exception.Create ('failed to connect');
  //
  result:=true;

end;

begin

  cmd := TCommandLineReader.create;
  cmd.declareString('ip', '192.168.1.254');
  cmd.declareInt('port', '22',22);
  cmd.declareString('username', 'mandatory');
  cmd.declareString('password', 'password or path to a pub key file, prompted if empty');
  cmd.declareString('command', 'rmdir mkdir put get dir');
  cmd.declareString('path', 'remote path','/');
  cmd.declareString('local_filename', 'optional, local path');
  cmd.declareString('dest_filename', 'optional, remote path');
  cmd.declareString('debug', 'true|false','false');
  cmd.parse(cmdline);

  if cmd.existsProperty('ip')=false then
    begin
    writeln('Usage: ssh --help');
    exit;
    end;

  host:=cmd.readstring('ip');
  port:=cmd.readint('port');
  username:=cmd.readstring('username');
  password:=cmd.readstring('password');
  verb:=cmd.readstring('command');
  path:=cmd.readstring('path');
  local_filename:=cmd.readstring('local_filename');
  dest_filename:=cmd.readstring('dest_filename');
  debug:= cmd.readString('debug')='true';
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
    if password='' then
      begin
      write('Password for ', host,' : ');
      readln(password);
      end;
    {
    log('libssh2_userauth_password...');
    if libssh2_userauth_password(session, pchar(username), pchar(password))<>0 then
      begin
      log('Authentication by password failed',1);
      exit;
      end;
    log('Authentication succeeded');
    }
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
    if verb='rename' then
    begin
    log('libssh2_sftp_rename');
      if libssh2_sftp_rename (sftp_session,pchar(path),pchar(dest_filename ))=0
         then log('cannot libssh2_sftp_rename');
    end;
    //
    if verb='rmdir' then
    begin
    //* Make a directory via SFTP */
    log('libssh2_sftp_rmdir');
    i := libssh2_sftp_rmdir(sftp_session, pchar(path));
    if i<>0 then log('libssh2_sftp_rmdir failed:'+inttostr(i),1);
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
    if i<>0 then log('libssh2_sftp_mkdir failed:'+inttostr(i),1);
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
    hfile := CreateFile(pchar(local_filename), GENERIC_READ , FILE_SHARE_READ or FILE_SHARE_WRITE, nil, OPEN_EXISTING , FILE_ATTRIBUTE_NORMAL, 0);
    if hfile=thandle(-1) then begin log('invalid handle',1);exit;end;
    while 1=1 do
      begin
      ReadFile (hfile,mem[0],sizeof(mem),size,nil);
      if size<=0 then break;
      i := libssh2_sftp_write(sftp_handle, @mem[0], size);
      if (i<>size) then begin log('libssh2_sftp_write error',1);break;end;
      log('libssh2_sftp_write:'+inttostr(i)+' bytes');
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
    if local_filename ='' then local_filename:=ExtractFileName (path);
    hfile := CreateFile(pchar(local_filename ), GENERIC_READ or GENERIC_WRITE, FILE_SHARE_READ or FILE_SHARE_WRITE, nil, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, 0);
    if hfile=thandle(-1) then begin log('invalid handle');exit;end;
    while 1=1 do
      begin
       i := libssh2_sftp_read(sftp_handle, @mem[0], sizeof(mem));
       if i>0 then
         begin
         //log(strpas(@mem[0]),1);
         WriteFile(hfile, mem[0], i, size, nil);
         log('libssh2_sftp_read:'+inttostr(i)+' bytes');
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
         tmp:='';
         //log(strpas(@mem[0])+#9+inttostr(attrs^.filesize),1);
         if (attrs.flags and LIBSSH2_SFTP_ATTR_SIZE)=LIBSSH2_SFTP_ATTR_SIZE
            then tmp:=inttostr(attrs.filesize ) ;
         if (attrs.permissions and LIBSSH2_SFTP_S_IFMT) = LIBSSH2_SFTP_S_IFDIR
            then tmp:='<DIR>';
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
  log('done');
end.



