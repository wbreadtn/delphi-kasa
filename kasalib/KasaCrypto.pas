unit KasaCrypto;

interface

uses
  SysUtils, Math
  ,IdGlobal
  ,IdHashMessageDigest
  ,IdHashSHA
  ,IdCoderMIME
  ,IdSSLOpenSSL
  ,DCPsha256
  ,DCPcrypt2
  ,DCPrijndael
  ;

procedure TBytesToTIdBytes(const Input: TBytes; var Output: TIdBytes);
function XORBytes(const A, B: TBytes): TBytes;
function BytesToHex(const ABytes: TBytes): string; overload;
function BytesToHex(const ABytes: TIdBytes): string;  overload;
function HexToBytes(const AHex: string): TBytes;
function StrToBytes(const AStr: string): TBytes;
function BytesToStr(const ABytes: TBytes): string;

function MD5Hash(const AData: TBytes): TBytes; overload;
function MD5Hash(const AData: string): TBytes; overload;
function SHA1Hash(const AData: TBytes): TBytes; overload;
function SHA1Hash(const AData: string): TBytes; overload;
function SHA256Hash(const AData: TBytes): TBytes; overload;
function SHA256Hash(const AData: string): TBytes; overload;

function AESEncryptCBCStr(const APlaintext: TBytes; const Key: TBytes; const IV: TBytes): TBytes;
function AESEncryptCBC(const Data: TBytes; const Key: TBytes; const IV: TBytes): TBytes;
function AESDecryptCBC(const Data: TBytes; const Key: TBytes; const IV: TBytes): TBytes;

//Not Crypto, but...
function EncodeBase64(const AInput: string): string;
function DecodeBase64(const AInput: string): string;

implementation

procedure TBytesToTIdBytes(const Input: TBytes; var Output: TIdBytes);
var
  I, L: Integer;
begin
  L := Length(Input);
  if Length(Output) <> L then
    SetLength(Output, L);
  if L > 0 then
    Move(Input[0], Output[0], L);
end;

function MD5Hash(const AData: TBytes): TBytes;
var
  MD5: TIdHashMessageDigest5;
  Data: TIdBytes;
begin
  MD5 := TIdHashMessageDigest5.Create;
  try
    TBytesToTIdBytes(AData, Data);
    result := TBytes(MD5.HashBytes(Data));
  finally
    MD5.Free;
  end;
end;

function MD5Hash(const AData: string): TBytes;
begin
  //Result := MD5Hash(TEncoding.UTF8.GetBytes(AData));
  Result := MD5Hash(TEncoding.Ascii.GetBytes(AData));
end;

function SHA1Hash(const AData: TBytes): TBytes;
var
  SHA1: TIdHashSHA1;
  Data: TIdBytes;
begin
  SHA1 := TIdHashSHA1.Create;
  try
    TBytesToTIdBytes(AData, Data);
    result := TBytes(SHA1.HashBytes(Data));
  finally
    SHA1.Free;
  end;
end;

function SHA1Hash(const AData: string): TBytes;
begin
  //Result := SHA1Hash(TEncoding.UTF8.GetBytes(AData));
  Result := SHA1Hash(TEncoding.Ascii.GetBytes(AData));
end;

function XORBytes(const A, B: TBytes): TBytes;
var
  i: Integer;
  MinLen: Integer;
begin
  MinLen := Min(Length(A), Length(B));
  SetLength(Result, MinLen);
  for i := 0 to MinLen - 1 do
    Result[i] := A[i] xor B[i];
end;


function BytesToHex(const ABytes: TBytes): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Length(ABytes) - 1 do
    Result := Result + Format('%.2x', [ABytes[i]]);
  result := Lowercase(Result);
end;

function BytesToHex(const ABytes: TIdBytes): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Length(ABytes) - 1 do
    Result := Result + Format('%.2x', [ABytes[i]]);
  result := Lowercase(Result);
end;

function HexToBytes(const AHex: string): TBytes;
var
  i: Integer;
begin
  SetLength(Result, Length(AHex) div 2);
  for i := 0 to Length(Result) - 1 do
    Result[i] := StrToInt('$' + Copy(AHex, i * 2 + 1, 2));
end;

function StrToBytes(const AStr: string): TBytes;
var
  i: Integer;
begin
  SetLength(Result, Length(AStr));
  for i := 0 to Length(Result) - 1 do
    Result[i] := StrToInt(Copy(AStr, i * 2 + 1, 2));
end;

function BytesToStr(const ABytes: TBytes): string;
var
  i: Integer;
begin
  Result := '';
  for i := 0 to Length(ABytes) - 1 do
    Result := Result + Chr(ABytes[i]);
end;
(*
function SHA256Hash(const AData: TBytes): TBytes;
var
  Data:TIdBytes;
begin
  IdSSLOpenSSL.LoadOpenSSLLibrary; // Ensure OpenSSL is loaded
  try
    with TIdHashSHA256.Create do
    try
      TBytesToTIdBytes(AData, Data);
      result := TBytes(HashBytes(Data));
    finally
      Free;
    end;
  finally
    IdSSLOpenSSL.UnloadOpenSSLLibrary;
  end;
end;
*)

function SHA256Hash(const AData: TBytes): TBytes;
var
  Hash: TDCP_sha256;
begin
  SetLength(Result, 32); // SHA256 always produces 32 bytes

  Hash := TDCP_sha256.Create(nil);
  try
    Hash.Init;
    if Length(AData) > 0 then
      Hash.Update(AData[0], Length(AData));
    Hash.Final(Result[0]);
  finally
    Hash.Free;
  end;
end;


function SHA256Hash(const AData: string): TBytes;
begin
  //Result := SHA256Hash(TEncoding.UTF8.GetBytes(AData));
  Result := SHA256Hash(TEncoding.Ascii.GetBytes(AData));
end;

function EncodeBase64(const AInput: string): string;
var
  Encoder: TIdEncoderMIME;
begin
  Encoder := TIdEncoderMIME.Create(nil);
  try
    Result := Encoder.Encode(AInput);
  finally
    Encoder.Free;
  end;
end;

function DecodeBase64(const AInput: string): string;
begin
  result := TIdDecoderMIME.DecodeString(AInput, IndyTextEncoding_ASCII);
end;

function AESEncryptCBCStr(const APlaintext: TBytes; const Key: TBytes; const IV: TBytes): TBytes;
var
  Cipher: TDCP_rijndael;
begin
  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.Init(Key[0], Length(Key) * 8, @IV[0]);
    SetLength(Result, Length(APlaintext));
    Cipher.EncryptCBC(APlaintext[0], Result[0], Length(APlaintext));
  finally
    Cipher.Free;
  end;
end;

function AESEncryptCBC(const Data: TBytes; const Key: TBytes; const IV: TBytes): TBytes;
var
  Cipher: TDCP_rijndael;
  DataLen: Integer;
begin
  if Length(Key) <> 16 then
    raise Exception.Create('AES-128 key must be 16 bytes');
  if Length(IV) <> 16 then
    raise Exception.Create('IV must be 16 bytes');
  if Length(Data) = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  // Data must be padded to block size before calling this function
  DataLen := Length(Data);
  if (DataLen mod 16) <> 0 then
    raise Exception.Create('Data must be padded to 16-byte blocks for AES-CBC');

  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.Init(Key[0], 128, @IV[0]); // 128-bit key
    SetLength(Result, DataLen);
    Cipher.EncryptCBC(Data[0], Result[0], DataLen);
  finally
    Cipher.Free;
  end;
end;

function AESDecryptCBC(const Data: TBytes; const Key: TBytes; const IV: TBytes): TBytes;
var
  Cipher: TDCP_rijndael;
  DataLen: Integer;
begin
  if Length(Key) <> 16 then
    raise Exception.Create('AES-128 key must be 16 bytes');
  if Length(IV) <> 16 then
    raise Exception.Create('IV must be 16 bytes');
  if Length(Data) = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  DataLen := Length(Data);
  if (DataLen mod 16) <> 0 then
    raise Exception.Create('Encrypted data must be in 16-byte blocks');

  Cipher := TDCP_rijndael.Create(nil);
  try
    Cipher.Init(Key[0], 128, @IV[0]); // 128-bit key
    SetLength(Result, DataLen);
    Cipher.DecryptCBC(Data[0], Result[0], DataLen);
  finally
    Cipher.Free;
  end;
end;

end.
