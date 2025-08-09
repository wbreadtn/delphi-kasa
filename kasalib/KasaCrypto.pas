unit KasaCrypto;

interface

uses
  SysUtils, Math
  ,IdGlobal
  ,IdHashMessageDigest
  ,IdHashSHA
  ,IdSSLOpenSSL
  ,DCPsha256
  ,DCPcrypt2
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

end.
