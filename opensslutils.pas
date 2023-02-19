unit OpenSSLUtils;

{$mode objfpc}{$H+}

interface

uses
  windows, SysUtils, classes,
  libeay32,utils;

procedure LoadSSL;
procedure FreeSSL;
function generate_rsa_key:boolean;
function mkcert:boolean;
function mkreq(cn:string;keyfile,csrfile:string):boolean;
function Convert2PEM(filename,export_pwd:string):boolean;
function Convert2PKCS12(filename,export_pwd:string):boolean;

function EncryptPub(sometext:string;var encrypted:string):boolean;
function DecryptPriv(ACryptedData:string):boolean;

implementation

type
ReadKeyChar = AnsiChar;
//ReadKeyChar = Byte;
PReadKeyChar = ^ReadKeyChar;

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

function Convert2PKCS12(filename,export_pwd:string):boolean;
var
  err_reason:integer;
  bp:pBIO;
  p12_cert:pPKCS12 = nil;
  pkey:pEVP_PKEY; x509_cert:pX509;
  additional_certs:pSTACK_OFX509 = nil;
begin

  bp := BIO_new_file(pchar('private.key'), 'r+');
  log('PEM_read_bio_PrivateKey');
  //password will be prompted
  pkey:=PEM_read_bio_PrivateKey(bp,nil,nil,nil);
  BIO_free(bp);

  bp := BIO_new_file(pchar('cert.crt'), 'r+');
  log('PEM_read_bio_X509');
  x509_cert:=PEM_read_bio_X509(bp,nil,nil,nil);
  BIO_free(bp);

  log('PKCS12_new');
  p12_cert := PKCS12_new();
  if p12_cert=nil then exit;


  log('PKCS12_create');
  p12_cert := PKCS12_create(pchar(export_pwd), nil, pkey, x509_cert, nil, 0, 0, 0, 0, 0);
  if p12_cert = nil then exit;

  log('i2d_PKCS12_bio');
  bp := BIO_new_file(pchar(filename), 'w+');
  err_reason:=i2d_PKCS12_bio(bp, p12_cert);
  BIO_free(bp);
  log(inttostr(err_reason));

  if x509_cert<>nil then X509_free(x509_cert); x509_cert := nil;
  if pkey<>nil then EVP_PKEY_free(pkey); pkey := nil;
  ERR_clear_error();
  PKCS12_free(p12_cert);
  result:=true;
end;

function Convert2PEM(filename,export_pwd:string):boolean;
const
  PKCS12_R_MAC_VERIFY_FAILURE =113;
var
    p12_cert:pPKCS12 = nil;
    pkey:pEVP_PKEY;
    x509_cert:pX509;
    additional_certs:pSTACK_OFX509 = nil;
    bp:pBIO;
    err_reason:integer;
begin
result:=false;
  bp := BIO_new_file(pchar(filename), 'r+');
  log('d2i_PKCS12_bio');
  //decode
  p12_cert:=d2i_PKCS12_bio(bp, nil);
  log('PKCS12_parse');
  //this is the export password, not the private key password
  err_reason:=PKCS12_parse(p12_cert, pchar(export_pwd), pkey, x509_cert, additional_certs);
  //if err_reason<>0 then
  log(inttostr(err_reason));
  BIO_free(bp);
  if err_reason =0 then exit;

  if p12_cert = nil then exit;


  //
  bp := BIO_new_file(pchar(GetCurrentDir+'\cert.crt'), 'w+');
  log('PEM_write_bio_X509');
  PEM_write_bio_X509(bp,x509_cert);
  BIO_free(bp);
  bp := BIO_new_file(pchar(GetCurrentDir+'\private.key'), 'w+');
  log('PEM_write_bio_PrivateKey');
  //the private key will have no password
  PEM_write_bio_PrivateKey(bp,pkey,nil{EVP_des_ede3_cbc()},nil,0,nil,nil);
  BIO_free(bp);
  //

  if x509_cert<>nil then X509_free(x509_cert); x509_cert := nil;
  if pkey<>nil then EVP_PKEY_free(pkey); pkey := nil;
  ERR_clear_error();
  PKCS12_free(p12_cert);
  result:=true;
end;

{
PEM Format
Most CAs (Certificate Authority) provide certificates in PEM format in Base64 ASCII encoded files.
The certificate file types can be .pem, .crt, .cer, or .key.
The .pem file can include the server certificate, the intermediate certificate and the private key in a single file.
The server certificate and intermediate certificate can also be in a separate .crt or .cer file.
The private key can be in a .key file.

PKCS#12 Format
The PKCS#12 certificates are in binary form, contained in .pfx or .p12 files.
The PKCS#12 can store the server certificate, the intermediate certificate and the private key in a single .pfx file with password protection.
These certificates are mainly used on the Windows platform.
}

//openssl pkcs12 -inkey priv.key -in cert.crt -export -out cert.pfx
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -nodes -> no encrypted private key
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -> encrypted private key
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.key -nodes -nocerts -> private key only
//openssl pkcs12 -in INFILE.p12 -out OUTFILE.crt -nokeys -> cert only
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
EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
//OpenSSL uses the X509 structure to represent an x509 certificate in memory
log('X509_new');
x509 := X509_new();
//Now we need to set a few properties of the certificate
ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
//
X509_gmtime_adj(X509_get_notBefore(x509), 0);
X509_gmtime_adj(X509_get_notAfter(x509), 31536000); // 365 * 24 * 3600
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

bp := BIO_new_file(pchar(GetCurrentDir+'\private.key'), 'w+');
//PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),pchar(''),0,nil,nil);
//if you want a prompt for passphrase
PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);

bp := BIO_new_file(pchar(GetCurrentDir+'\cert.crt'), 'w+');
PEM_write_bio_X509(bp,x509);
//
//bp := BIO_new_file(pchar(GetCurrentDir+'\cert.crt'), 'w+');
//PEM_write_bio_X509(bp,x509);
//PEM_write_bio_PrivateKey(bp,pkey,EVP_des_ede3_cbc(),nil,0,nil,nil);
//
EVP_PKEY_free(pkey);
X509_free(x509);
//
result:=true;
end;

//to sign a csr
//openssl x509 -req -in device.csr -CA rootCA.pem -CAkey rootCA.key -CAcreateserial -out device.crt -days 500 -sha256
function mkreq(cn:string;keyfile,csrfile:string):boolean;
var
ret:integer;
rsa:pRSA;
bp:pBIO;
req:pX509_REQ;
key:pEVP_PKEY;
name:pX509_NAME;
begin
result:=false;


        log('RSA_generate_key');
	rsa := RSA_generate_key(
    2048,   //* number of bits for the key - 2048 is a sensible value */
    RSA_F4, //* exponent - RSA_F4 is defined as 0x10001L */
    nil,   //* callback - can be NULL if we aren't displaying progress */
    nil    //* callback argument - not needed in this case */
);

        bp := BIO_new_file(pchar(GetCurrentDir+'\'+keyfile), 'w+');
        //the private key will have no password
        log('PEM_write_bio_RSAPrivateKey');
        ret := PEM_write_bio_RSAPrivateKey(bp, rsa, nil, nil, 0, nil, nil);
	BIO_free(bp);

        log('X509_REQ_new');
	req := X509_REQ_new();

	if req=nil then exit;

        log('EVP_PKEY_new');
	key := EVP_PKEY_new();
	EVP_PKEY_assign(key,EVP_PKEY_RSA,PCharacter(rsa));
	X509_REQ_set_version(req, 0);
	X509_REQ_set_pubkey(req, key);

        log('X509_REQ_get_subject_name');
	name := X509_NAME_new; //X509_REQ_get_subject_name(req);
        log('X509_NAME_add_entry_by_txt');
	X509_NAME_add_entry_by_txt(name, 'CN', MBSTRING_ASC,pchar(cn), -1, -1, 0);
        log('X509_REQ_set_subject_name');
        ret:=X509_REQ_set_subject_name(Req, name); //since X509_REQ_get_subject_name(req) failed on me

        log('X509_REQ_sign');
	X509_REQ_sign(req, key, EVP_sha1());

	EVP_PKEY_free(key);

        bp := BIO_new_file(pchar(GetCurrentDir+'\'+csrfile), 'w+');
        log('PEM_write_bio_X509_REQ');
        PEM_write_bio_X509_REQ(bp, req);
	BIO_free(bp);

	X509_REQ_free(req);

result:=true;

end;

function LoadPublicKey(KeyFile: string) :pEVP_PKEY ;
var
  mem: pBIO;
  k: pEVP_PKEY;
  rc:integer=0;
begin
  k:=nil;
  mem := BIO_new(BIO_s_file()); //BIO типа файл
  log('BIO_read_filename');
  rc:=BIO_read_filename(mem, PAnsiChar(KeyFile)); // чтение файла ключа в BIO
  log(inttostr(rc));
  try
    result := PEM_read_bio_PUBKEY(mem, k, nil, nil); //преобразование BIO  в структуру pEVP_PKEY, третий параметр указан nil, означает для ключа не нужно запрашивать пароль
  finally
    BIO_free_all(mem);
  end;
end;

function LoadPrivateKey(KeyFile: string) :pEVP_PKEY;
var
  mem: pBIO;
  k: pEVP_PKEY;
begin
  k := nil;
  mem := BIO_new(BIO_s_file());
  BIO_read_filename(mem, PAnsiChar(KeyFile));
  try
    result := PEM_read_bio_PrivateKey(mem, k, nil, nil);
  finally
    BIO_free_all(mem);
  end;
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
//or ssh-keygen -f public.pem -i -m PKCS8 > key.pub
//copy the pub key to the authorized keys
//cat key.pub >> ~/.ssh/authorized_keys
//should work as well : ssh-copy-id -i /path/to/key/file user@host.com
//Remember that .ssh folder has to be 700. The authorized_keys file should be 600
//or the other way (no success here for now)
//on the remote ssh server, generate a key pair
//ssh-keygen -b 2048 -t rsa -m PEM
//and use either the pub or priv key from there
//see also https://docs.oracle.com/en/cloud/cloud-at-customer/occ-get-started/generate-ssh-key-pair.html
function generate_rsa_key:boolean;
var

	ret:integer; //= 0;
	rsa:pRSA;//				 = nil;
	bne:pBIGNUM;// = nil;
	bp_public:pBIO;// = nil;
  bp_private:pBIO;// = nil;

	bits:integer; // = 2048;
	e:ulong; // = RSA_F4;
        //
        pkey:PEVP_PKEY;
  label free_all;
begin
  //
  ret:=0;
  rsa:=nil;
  bne:=nil;
  bp_public :=nil;
  bp_private :=nil;
  bits:=2048;
  e :=RSA_F4;
	// 1. generate rsa key
	bne := BN_new();
	ret := BN_set_word(bne,e);
	if ret <> 1 then goto free_all;

	rsa := RSA_new();
	ret := RSA_generate_key_ex(rsa, bits, bne, nil);
	if ret <> 1 then goto free_all;
        log('1. generate rsa key OK');



	// 2. save public key
	bp_public := BIO_new_file(pchar(GetCurrentDir+'\public.pem'), 'w+');
	//ret := PEM_write_bio_RSAPublicKey(bp_public, rsa);
        log('EVP_PKEY_new');
        pkey := EVP_PKEY_new();
        log('EVP_PKEY_assign_RSA');
        EVP_PKEY_assign(pkey,EVP_PKEY_RSA,PCharacter(rsa));
        ret:=PEM_write_bio_PUBKEY (bp_public ,pkey);
	if ret <>1 then goto free_all;
        log('2. save public key OK');

	// 3. save private key
	bp_private := BIO_new_file(pchar(GetCurrentDir+'\private.pem'), 'w+');
        //the private key will have no password
	ret := PEM_write_bio_RSAPrivateKey(bp_private, rsa, nil, nil, 0, nil, nil);
        log('3. save private key');

	// 4. free
free_all:

	BIO_free_all(bp_public);
	BIO_free_all(bp_private);
	RSA_free(rsa);
	BN_free(bne);

	if ret=1 then result:=true else result:=false;
end;

//RSA_public_encrypt, RSA_private_decrypt - RSA public key cryptography
//versus
//RSA_private_encrypt, RSA_public_decrypt - low-level signature operations ... using the private key rsa
function EncryptPub(sometext:string;var encrypted:string):boolean;
var
	rsa: pRSA; // структура RSA
	size: Integer;
	FCryptedBuffer: pointer; // Выходной буфер
	b64, mem: pBIO;
	str, data: AnsiString;
	len, b64len: Integer;
	penc64: PAnsiChar;
	err: Cardinal;
        //
        //FPublicKey: pEVP_PKEY;
        FKey: pEVP_PKEY=nil;
        bp:pBIO;
begin
  result:=false;
  FKey := LoadPublicKey('public.pem');

  //load the private key but then you lose the benefit of private/public key...
  //unless you want both end to encrypt/decrypt with a unique private key
  //FKey := LoadPrivateKey('private.pem');

  //
  if FKey=nil then exit;
  //
	rsa := EVP_PKEY_get1_RSA(FKey); // Получение RSA структуры
	EVP_PKEY_free(FKey); // Освобождение pEVP_PKEY
	size := RSA_size(rsa); // Получение размера ключа
	GetMem(FCryptedBuffer, size); // Определение размера выходящего буфера
	str := AnsiString(sometext); // Строка для шифрования

	//Шифрование
	len := RSA_public_encrypt(Length(str),  // Размер строки для шифрования
							  PAnsiChar(str),  // Строка шифрования
							  FCryptedBuffer,  // Выходной буфер
							  rsa, // Структура ключа
							  RSA_PKCS1_PADDING // Определение выравнивания
							  );

	if len > 0 then // длина буфера после шифрования
	  begin
          log(inttostr(len));
	  // полученный бинарный буфер преобразуем в человекоподобный base64
		b64 := BIO_new(BIO_f_base64); // BIO типа base64
		mem := BIO_push(b64, BIO_new(BIO_s_mem)); // Stream
		try
			BIO_write(mem, FCryptedBuffer, len); // Запись в Stream бинарного выходного буфера
			BIO_flush(mem);
			b64len := BIO_get_mem_data(mem, penc64); //получаем размер строки в base64
			SetLength(data, b64len); // задаем размер выходному буферу
			Move(penc64^, PAnsiChar(data)^, b64len); // Перечитываем в буфер data строку в base64
                        encrypted:=data;
		finally
			BIO_free_all(mem);
		end;
	  end
	  else
	  begin // читаем ошибку, если длина шифрованной строки -1
		err := ERR_get_error;
		repeat
			log(string(ERR_error_string(err, nil)),1);
			err := ERR_get_error;
		until err = 0;
	  end;
	RSA_free(rsa);
        result:=true;
end;

{
-Generate private key
openssl genrsa 2048 > private2.pem
-Generate public key from private
openssl rsa -in private2.pem -pubout > public2.pem
}
function DecryptPriv(ACryptedData:string):boolean;
var
  rsa: pRSA=nil;
  out_: AnsiString;
  str, data: PAnsiChar;
  len, b64len: Integer;
  penc64: PAnsiChar;
  b64, mem, bio_out, bio: pBIO;
  size: Integer;
  err: Cardinal;
  //
  FKey: pEVP_PKEY=nil;
  bp:pBIO;
  x: pEVP_PKEY;
begin

        //FKey:=LoadPublicKey('public.pem');
        FKey:=LoadPrivateKey('private.pem');
        if FKey = nil then
        begin
        	err := ERR_get_error;
        	repeat
        		log(string(ERR_error_string(err, nil)),1);
        		err := ERR_get_error;
        	until err = 0;
                exit;
        	end;

        //
        log('EVP_PKEY_get1_RSA');
	rsa := EVP_PKEY_get1_RSA(FKey);
        EVP_PKEY_free(FKey);
        if rsa=nil then exit;


        //we could load the rsa directly from the private key as well
        {
        bp := BIO_new_file(pchar('private.pem'), 'r+');
        log('PEM_read_bio_RSAPrivateKey');
        rsa:=PEM_read_bio_RSAPrivateKey   (bp,nil,nil,nil);
        BIO_free(bp);
        if rsa=nil then exit;
        }

        log('RSA_size');
        size := RSA_size(rsa);
        log(inttostr(size));
	GetMem(data, size);  // Определяем размер выходному буферу дешифрованной строки
	GetMem(str, size); // Определяем размер шифрованному буферу после конвертации из base64

	//Decode base64
	b64 := BIO_new(BIO_f_base64);
	mem := BIO_new_mem_buf(PAnsiChar(ACryptedData), Length(ACryptedData));
	BIO_flush(mem);
	mem := BIO_push(b64, mem);
	BIO_read(mem, str , Length(ACryptedData)); // Получаем шифрованную строку в бинарном виде
	BIO_free_all(mem);
	// Дешифрование
        log('RSA_private_decrypt');
	len := RSA_private_decrypt(size, PCharacter(str), PCharacter(data), rsa, RSA_PKCS1_PADDING);
        log(inttostr(len));
        if len > 0 then
	begin
	// в буфер data данные расшифровываются с «мусором» в конца, очищаем, определяем размер переменной out_ и переписываем в нее нужное количество байт из data
		SetLength(out_, len);
		Move(data^, PAnsiChar(out_ )^, len);
                writeln(out_);
	end
	else
        begin // читаем ошибку, если длина шифрованной строки -1
		err := ERR_get_error;
		repeat
			writeln(string(ERR_error_string(err, nil)));
			err := ERR_get_error;
		until err = 0;
	end;
end;

end.

