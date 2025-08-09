unit KasaKLAPController;

interface

uses
  System.SysUtils, System.Classes, IdHttp,
  Winapi.Windows,
  System.JSON, {System.Hash,} System.NetEncoding, System.DateUtils
  ,KasaCrypto
  ,System.Math
  ,IdHMACMD5
  //,IdHashMessageDigest
  ,IdGlobal
  ,IdCookieManager
  ,IdCookie
  ,IdHashSHA
  ,IdSSLOpenSSL
  ,IdURI
  ,IdIOHandler
  ,IdIOHandlerSocket
  ,IdIOHandlerStack
  ,IdException
  ,IdExceptionCore
  ,IOUtils
  ,SuperObject
  ;

type
  TKlapVersion = (kvV1, kvV2, kvV2_alt); // Added kvV0 for XOR protocol
  TKasaLogger = procedure (Sender: TObject; Text: string) of object;

  THTTPIOHandlerHelper = class
  private
    FIdHTTP: TIdHTTP;
    FProxyHost: string;
    FProxyPort: Integer;
    FProxyUser: string;
    FProxyPassword: string;
    FUseProxy: Boolean;
    FKasaLogger: TKasaLogger;
    procedure CustomizeIOHandler(AIOHandler: TIdIOHandler);
    procedure CheckHeaders(AHeaders: TStrings; var Raw: string);
    function BuildRawHTTPRequest(const AMethod, APath, AHost: string;
      const AHeaders: TStrings; const ABody: string = ''): string; overload;
    function BuildRawHTTPRequest(const AMethod, APath, AHost: string;
      const AHeaders: TStrings; ARequestStream: TStream): string; overload;
    function BuildProxyHTTPRequest(const AMethod, AURL: string;
      const AHeaders: TStrings; const ABody: string = ''): string; overload;
    function BuildProxyHTTPRequest(const AMethod, AURL: string;
      const AHeaders: TStrings; ARequestStream: TStream): string; overload;
  public
    constructor Create;
    destructor Destroy; override;
    procedure SetProxy(const AHost: string; APort: Integer; const AUser: string = ''; const APassword: string = '');
    procedure ClearProxy;
    function SendRawHTTPRequest(AURL: string; Seq:Integer; AMethod: string;
      const AHeaders: TStrings; ResponseHeaders: TStrings; const ABody: string = ''): string; overload;
    procedure SendRawHTTPRequest(AURL: string; Seq:Integer; AMethod: string;
      const AHeaders: TStrings; ARequestStream: TStream; ResponseHeaders: TStrings; AResponseStream: TStream); overload;
    function SendCustomGETRequest(const AURL: string): string;
    function SendCustomPOSTRequest(const AURL: string; const APostData: string): string;
    property KasaLogger: TKasaLogger read FKasaLogger write FKasaLogger;
  end;

  TKasaKLAPClient = class
  private
    FHost: string;
    FPort: Integer;
    FUsername: string;
    FPassword: string;
    FLocalSeed: TBytes;
    FRemoteSeed: TBytes;
    FAuthHash: TBytes;
    FSessionKey: TBytes;
    FSessionKeyMD5: TBytes;
    FSessionKeySHA256: TBytes;
    FSessionID: string;
    FTimeOut: string;
    FSeqNum: Integer;
    FEncryptionKey: TBytes;
    FBaseIV: TBytes;
    FSignatureKey: TBytes;
    FKlapVersion: TKlapVersion;
    FAltCredentials: ISuperobject;
    FKasaLogger: TKasaLogger;
    function GenerateRandomBytes(ALength: Integer): TBytes;
    function KlapEncrypt(const APlaintext: TBytes): TBytes;
    function KlapDecrypt(const AEncryptedData: TBytes): TBytes;
    function CalculateAuthHash(KlapVersion: TKlapVersion; aUsername, aPassword: string): TBytes;
    procedure InitializeEncryption;
    function PKCS7Pad(const Data: TBytes; BlockSize: Integer): TBytes;
    function PKCS7Unpad(const Data: TBytes): TBytes;
  public
    constructor Create(const AHost: string; APort: Integer = 80;
                      const AUsername: string = 'admin'; const APassword: string = '');
    destructor Destroy; override;

    function Handshake(var StatusText: string): Boolean;
    function SendCommand(ACommand: string; var Res: string): boolean;
    function PerformSend(Command: string): Boolean;
    function TurnOn: Boolean;
    function TurnOff: Boolean;
    function GetDeviceInfo(var Res: string): boolean;

    property Host: string read FHost write FHost;
    property Port: Integer read FPort write FPort;
    property Username: string read FUsername write FUsername;
    property Password: string read FPassword write FPassword;
    property KlapVersion: TKlapVersion read FKlapVersion write FKlapVersion;
    property AltCredentials: ISuperobject read FAltCredentials write FAltCredentials;
    property KasaLogger: TKasaLogger read FKasaLogger write FKasaLogger;
  end;

implementation

constructor THTTPIOHandlerHelper.Create;
begin
  inherited Create;
  FKasaLogger := nil;
  FIdHTTP := TIdHTTP.Create(nil);

  // Don't create SSL handler by default - create it only when needed
  FIdHTTP.IOHandler := TIdIOHandlerStack.Create(FIdHTTP);

  // Initialize proxy settings
  FUseProxy := False;
  FProxyHost := '';
  FProxyPort := 0;
  FProxyUser := '';
  FProxyPassword := '';

  // Customize the IOHandler
  CustomizeIOHandler(FIdHTTP.IOHandler);
end;

destructor THTTPIOHandlerHelper.Destroy;
begin
  FIdHTTP.Free;
  inherited Destroy;
end;

procedure THTTPIOHandlerHelper.CustomizeIOHandler(AIOHandler: TIdIOHandler);
begin
  if AIOHandler is TIdSSLIOHandlerSocketOpenSSL then
  begin
    with TIdSSLIOHandlerSocketOpenSSL(AIOHandler) do
    begin
      SSLOptions.Method := sslvTLSv1_2;
      SSLOptions.Mode := sslmClient;
      SSLOptions.VerifyMode := [];
      SSLOptions.VerifyDepth := 0;
    end;
  end;

  // Set timeouts and buffer sizes
  AIOHandler.ConnectTimeout := 30000;
  AIOHandler.ReadTimeout := 30000;
end;

procedure THTTPIOHandlerHelper.CheckHeaders(AHeaders: TStrings; var Raw: string);
var
  i: Integer;
begin
  // Add custom headers
  if Assigned(AHeaders) then
  begin
    for i := 0 to AHeaders.Count - 1 do
    begin
      if AHeaders[i] <> '' then
        Raw := Raw + AHeaders[i] + #13#10;
    end;
  end;
end;

function THTTPIOHandlerHelper.BuildRawHTTPRequest(const AMethod, APath, AHost: string;
  const AHeaders: TStrings; const ABody: string = ''): string;
var
  ContentLength: string;
begin
  Result := AMethod + ' ' + APath + ' HTTP/1.0' + #13#10;
  Result := Result + 'Host: ' + AHost + #13#10;

  CheckHeaders(AHeaders, Result);

  // Add Content-Length for POST/PUT requests
  if (ABody <> '') and (UpperCase(AMethod) <> 'GET') then
  begin
    ContentLength := 'Content-Length: ' + IntToStr(Length(UTF8Encode(ABody)));
    Result := Result + ContentLength + #13#10;
  end;

  // End headers
  Result := Result + #13#10;

  // Add body if present
  if ABody <> '' then
    Result := Result + ABody;
end;

function THTTPIOHandlerHelper.BuildRawHTTPRequest(const AMethod, APath, AHost: string;
  const AHeaders: TStrings; ARequestStream: TStream): string;
var
  i: Integer;
  ContentLength: string;
begin
  Result := AMethod + ' ' + APath + ' HTTP/1.0' + #13#10;
  Result := Result + 'Host: ' + AHost + #13#10;

  CheckHeaders(AHeaders, Result);

  // Add Content-Length for POST/PUT requests with stream data
  if Assigned(ARequestStream) and (ARequestStream.Size > 0) and (UpperCase(AMethod) <> 'GET') then
  begin
    ContentLength := 'Content-Length: ' + IntToStr(ARequestStream.Size);
    Result := Result + ContentLength + #13#10;
  end;

  // End headers
  Result := Result + #13#10;
end;

procedure THTTPIOHandlerHelper.SetProxy(const AHost: string; APort: Integer; const AUser: string = ''; const APassword: string = '');
begin
  FProxyHost := AHost;
  FProxyPort := APort;
  FProxyUser := AUser;
  FProxyPassword := APassword;
  FUseProxy := (AHost <> '') and (APort > 0);
end;

procedure THTTPIOHandlerHelper.ClearProxy;
begin
  FUseProxy := False;
  FProxyHost := '';
  FProxyPort := 0;
  FProxyUser := '';
  FProxyPassword := '';
end;

function THTTPIOHandlerHelper.BuildProxyHTTPRequest(const AMethod, AURL: string;
  const AHeaders: TStrings; const ABody: string = ''): string;
var
  i: Integer;
  ContentLength: string;
  ProxyAuth: string;
begin
  // For proxy requests, use the full URL in the request line
  Result := AMethod + ' ' + AURL + ' HTTP/1.0' + #13#10;

  // Add proxy authentication if credentials are provided
  if (FProxyUser <> '') then
  begin
    ProxyAuth := EncodeBase64(FProxyUser + ':' + FProxyPassword);
    Result := Result + 'Proxy-Authorization: Basic ' + ProxyAuth + #13#10;
  end;

  CheckHeaders(AHeaders, Result);

  // Add Content-Length for POST/PUT requests
  if (ABody <> '') and (UpperCase(AMethod) <> 'GET') then
  begin
    ContentLength := 'Content-Length: ' + IntToStr(Length(UTF8Encode(ABody)));
    Result := Result + ContentLength + #13#10;
  end;

  // End headers
  Result := Result + #13#10;

  // Add body if present
  if ABody <> '' then
    Result := Result + ABody;
end;

function THTTPIOHandlerHelper.BuildProxyHTTPRequest(const AMethod, AURL: string;
  const AHeaders: TStrings; ARequestStream: TStream): string;
var
  i: Integer;
  ContentLength: string;
  ProxyAuth: string;
begin
  // For proxy requests, use the full URL in the request line
  Result := AMethod + ' ' + AURL + ' HTTP/1.0' + #13#10;

  // Add proxy authentication if credentials are provided
  if (FProxyUser <> '') then
  begin
    ProxyAuth := EncodeBase64(FProxyUser + ':' + FProxyPassword);
    Result := Result + 'Proxy-Authorization: Basic ' + ProxyAuth + #13#10;
  end;

  CheckHeaders(AHeaders, Result);

  // Add Content-Length for POST/PUT requests with stream data
  if Assigned(ARequestStream) and (ARequestStream.Size > 0) and (UpperCase(AMethod) <> 'GET') then
  begin
    ContentLength := 'Content-Length: ' + IntToStr(ARequestStream.Size);
    Result := Result + ContentLength + #13#10;
  end;

  // End headers
  Result := Result + #13#10;
end;

procedure THTTPIOHandlerHelper.SendRawHTTPRequest(AURL: string; Seq:Integer; AMethod: string;
  const AHeaders: TStrings; ARequestStream: TStream; ResponseHeaders: TStrings; AResponseStream: TStream);
var
  URI: TIdURI;
  RawRequest: string;
  IOHandler: TIdIOHandler;
  Port: Integer;
  IsSSL: Boolean;
  ResponseBuffer: TIdBytes;
  TempStream: TMemoryStream;
  HeadersEnd: Integer;
  HeadersComplete: Boolean;
  LineBuffer: string;
  TotalBytesRead: Integer;
  ChunkSize: Integer;
  StatusLine: string;
  ResponseCode: Integer;
  ResponseText: string;
  DoAppend: boolean;
  RequestPath: string;
const
  BUFFER_SIZE = 8192;
begin
  if not Assigned(AResponseStream) then
    raise Exception.Create('Response stream cannot be nil');

  URI := TIdURI.Create(AURL);
  try
    IsSSL := UpperCase(URI.Protocol) = 'HTTPS';
    Port := StrToIntDef(URI.Port, IfThen(IsSSL, 443, 80));

    // Create appropriate IOHandler based on protocol
    if IsSSL then
    begin
      // Replace with SSL handler for HTTPS
      FIdHTTP.IOHandler.Free;
      FIdHTTP.IOHandler := TIdSSLIOHandlerSocketOpenSSL.Create(FIdHTTP);
      CustomizeIOHandler(FIdHTTP.IOHandler);
    end else
    begin
      // Ensure we have a non-SSL handler for HTTP
      if FIdHTTP.IOHandler is TIdSSLIOHandlerSocketOpenSSL then
      begin
        FIdHTTP.IOHandler.Free;
        FIdHTTP.IOHandler := TIdIOHandlerStack.Create(FIdHTTP);
        CustomizeIOHandler(FIdHTTP.IOHandler);
      end;
    end;

    IOHandler := FIdHTTP.IOHandler;
    TempStream := TMemoryStream.Create;
    try
      // Connect to the server (or proxy)
      if FUseProxy then
      begin
        IOHandler.Host := FProxyHost;
        IOHandler.Port := FProxyPort;
      end else
      begin
        IOHandler.Host := URI.Host;
        IOHandler.Port := Port;
      end;
      IOHandler.Open;

      // Build the raw HTTP request headers
      if FUseProxy then
      begin
        if Seq <> 0
          then AURL := AURL + '?seq='+IntToStr(Seq);
        if assigned(FKasaLogger) then FKasaLogger(self,'Debug - AURL Path: ' + AURL);
        RawRequest := BuildProxyHTTPRequest(AMethod, AURL, AHeaders, ARequestStream)
      end
      else
      begin
        RequestPath := URI.Path + URI.Document;
        if Seq <> 0
          then RequestPath := RequestPath + '?seq='+IntToStr(Seq);
        if assigned(FKasaLogger) then
          begin
            FKasaLogger(self,'Debug - Full URL: ' + AURL);
            FKasaLogger(self,'Debug - URI.Path: ' + URI.Path);
            FKasaLogger(self,'Debug - URI.Document: ' + URI.Document);
            FKasaLogger(self,'Debug - Combined Path: ' + RequestPath);
          end;
        RawRequest := BuildRawHTTPRequest(AMethod, RequestPath, URI.Host, AHeaders, ARequestStream);
      end;

      // Send the request headers
      IOHandler.Write(RawRequest, IndyTextEncoding_ASCII);    //utf8

      // Send the request body from stream if present
      if Assigned(ARequestStream) and (ARequestStream.Size > 0) then
      begin
        ARequestStream.Position := 0;
        IOHandler.Write(ARequestStream, 0, false);
      end;

      // Read the response headers first
      HeadersComplete := False;
      HeadersEnd := 0;
      ResponseCode := -1;
      StatusLine := '';

      while IOHandler.Connected and not HeadersComplete do
      begin
        try
          LineBuffer := IOHandler.ReadLn(#13#10, 5000, -1, IndyTextEncoding_UTF8);

          // Capture the status line (first line of response)
          if StatusLine = '' then
          begin
            StatusLine := LineBuffer;
            // Parse status line: "HTTP/1.1 400 Bad Request"
            if Pos('HTTP/', StatusLine) = 1 then
            begin
              try
                // Extract response code from status line
                ResponseText := Copy(StatusLine, Pos(' ', StatusLine) + 1, Length(StatusLine));
                ResponseCode := StrToIntDef(Copy(ResponseText, 1, Pos(' ', ResponseText) - 1), -1);
              except
                ResponseCode := -1;
              end;
            end;
          end;

          LineBuffer := LineBuffer + #13#10;

          // Write to temp stream for processing
          TempStream.Write(LineBuffer[1], Length(LineBuffer) * SizeOf(Char));

          // Check for end of headers (empty line)
          if Trim(LineBuffer) = '' then
          begin
            HeadersComplete := True;
            HeadersEnd := TempStream.Position;
            if ResponseHeaders <> nil then
              begin
                TempStream.Position := 0;
                ResponseHeaders.LoadFromStream(TempStream, TEncoding.Unicode);
                ResponseHeaders.Delete(ResponseHeaders.Count-1); //Last item will always be blank in this case
                TempStream.Clear;
              end;
          end;

        except
          on E: Exception do
          begin
            // Handle timeout or other read errors
            Break;
          end;
        end;
      end;

      // Handle HTTP error codes by raising an exception (similar to standard TIdHTTP behavior)
      if (ResponseCode >= 400) and (ResponseCode < 600) then
      begin
        raise EIdHTTPProtocolException.CreateError(ResponseCode, ResponseText, StatusLine);
      end;

      // Continue reading response body
      TotalBytesRead := 0;
      while IOHandler.Connected do
      begin
        try
          // Check if there's data available to read
          if IOHandler.InputBufferIsEmpty then
          begin
            IOHandler.CheckForDataOnSource(100); // 100ms timeout
            if IOHandler.InputBufferIsEmpty then
              Break;
          end;

          // Read available data from input buffer
          ChunkSize := IOHandler.InputBuffer.Size;
          if ChunkSize > BUFFER_SIZE then
            ChunkSize := BUFFER_SIZE;

          DoAppend := false;
          if ChunkSize > 0 then
          begin
            SetLength(ResponseBuffer, ChunkSize);
            IOHandler.InputBuffer.ExtractToBytes(ResponseBuffer, ChunkSize, DoAppend);
            TempStream.Write(ResponseBuffer[0], ChunkSize);
            Inc(TotalBytesRead, ChunkSize);
            DoAppend := true;
          end else
          begin
            // No data available, exit loop
            Break;
          end;

        except
          on EIdConnClosedGracefully do
            Break;
          on EIdReadTimeout do
            Break;
          on E: Exception do
            Break;
        end;
      end;

      // Copy complete response to output stream
      TempStream.Position := 0;
      AResponseStream.CopyFrom(TempStream, TempStream.Size);
      AResponseStream.Position := 0;

    finally
      TempStream.Free;
      if IOHandler.Connected then
        IOHandler.Close;
    end;

  finally
    URI.Free;
  end;
end;

function THTTPIOHandlerHelper.SendRawHTTPRequest(AURL: string; Seq:Integer; AMethod: string;
  const AHeaders: TStrings; ResponseHeaders: TStrings; const ABody: string = ''): string;
var
  URI: TIdURI;
  RawRequest: string;
  Response: string;
  IOHandler: TIdIOHandler;
  Port: Integer;
  IsSSL: Boolean;
  RequestPath: string;
begin
  Result := '';
  URI := TIdURI.Create(AURL);
  try
    IsSSL := UpperCase(URI.Protocol) = 'HTTPS';
    Port := StrToIntDef(URI.Port, IfThen(IsSSL, 443, 80));

    // Create appropriate IOHandler based on protocol
    if IsSSL then
    begin
      // Replace with SSL handler for HTTPS
      FIdHTTP.IOHandler.Free;
      FIdHTTP.IOHandler := TIdSSLIOHandlerSocketOpenSSL.Create(FIdHTTP);
      CustomizeIOHandler(FIdHTTP.IOHandler);
    end else
    begin
      // Ensure we have a non-SSL handler for HTTP
      if FIdHTTP.IOHandler is TIdSSLIOHandlerSocketOpenSSL then
      begin
        FIdHTTP.IOHandler.Free;
        FIdHTTP.IOHandler := TIdIOHandlerStack.Create(FIdHTTP);
        CustomizeIOHandler(FIdHTTP.IOHandler);
      end;
    end;

    IOHandler := FIdHTTP.IOHandler;

    try
      // Connect to the server (or proxy)
      if FUseProxy then
      begin
        IOHandler.Host := FProxyHost;
        IOHandler.Port := FProxyPort;
      end else
      begin
        IOHandler.Host := URI.Host;
        IOHandler.Port := Port;
      end;
      IOHandler.Open;

      // Build the raw HTTP request
      if FUseProxy then
      begin
        if Seq <> 0
          then AURL := AURL + '?seq='+IntToStr(Seq);
        if assigned(FKasaLogger) then FKasaLogger(self,'Debug - AURL Path: ' + AURL);
        RawRequest := BuildProxyHTTPRequest(AMethod, AURL, AHeaders, ABody)
      end
      else
      begin
        RequestPath := URI.Path + URI.Document;
        if Seq <> 0
          then RequestPath := RequestPath + '?seq='+IntToStr(Seq);
        if assigned(FKasaLogger) then
          begin
            FKasaLogger(self,'Debug - Full URL: ' + AURL);
            FKasaLogger(self,'Debug - URI.Path: ' + URI.Path);
            FKasaLogger(self,'Debug - URI.Document: ' + URI.Document);
            FKasaLogger(self,'Debug - Combined Path: ' + RequestPath);
          end;

        RawRequest := BuildRawHTTPRequest(AMethod, RequestPath, URI.Host, AHeaders, ABody);
      end;

      // Send the raw request
      IOHandler.Write(RawRequest, IndyTextEncoding_UTF8);

      // Read the response
      Response := '';
      while IOHandler.Connected do
      begin
        try
          Response := Response + IOHandler.ReadLn(#13#10, 1000, -1, IndyTextEncoding_UTF8);
          Response := Response + #13#10;
        except
          on E: Exception do
          begin
            // Handle timeout or connection closed
            Break;
          end;
        end;
      end;

      Result := Response;

    finally
      if IOHandler.Connected then
        IOHandler.Close;
    end;

  finally
    URI.Free;
  end;
end;

function THTTPIOHandlerHelper.SendCustomGETRequest(const AURL: string): string;
var
  Headers: TStringList;
begin
  Headers := TStringList.Create;
  try
    Headers.Add('Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
    Headers.Add('Accept-Language: en-US,en;q=0.5');
    Headers.Add('Accept-Encoding: gzip, deflate');
    Headers.Add('Cache-Control: no-cache');

    Result := SendRawHTTPRequest(AURL, 0, 'GET', Headers, nil);
  finally
    Headers.Free;
  end;
end;

function THTTPIOHandlerHelper.SendCustomPOSTRequest(const AURL: string;
  const APostData: string): string;
var
  Headers: TStringList;
begin
  Headers := TStringList.Create;
  try
    Headers.Add('Content-Type: application/x-www-form-urlencoded');
    Headers.Add('Accept: application/json, text/plain, */*');
    Headers.Add('Cache-Control: no-cache');

    Result := SendRawHTTPRequest(AURL, 0, 'POST', Headers, nil, APostData);
  finally
    Headers.Free;
  end;
end;

constructor TKasaKLAPClient.Create(const AHost: string; APort: Integer;
                                  const AUsername, APassword: string);
begin
  inherited Create;
  FKasaLogger := nil;
  FHost := AHost;
  FPort := APort;
  FUsername := AUsername;
  FPassword := APassword;
  FSeqNum := 0;
end;

destructor TKasaKLAPClient.Destroy;
begin
  inherited;
end;

function TKasaKLAPClient.GenerateRandomBytes(ALength: Integer): TBytes;
var
  i: Integer;
begin
  SetLength(Result, ALength);
  Randomize;
  for i := 0 to ALength - 1 do
    Result[i] := Random(256);
end;

function TKasaKLAPClient.CalculateAuthHash(KlapVersion: TKlapVersion; aUsername, aPassword: string): TBytes;
var
  UsernameHash, PasswordHash: TBytes;
begin
  case KlapVersion of
    kvV1:
      begin
        // auth_hash = md5(md5(username) + md5(password))
        UsernameHash := MD5Hash(aUsername);
        PasswordHash := MD5Hash(aPassword);

        SetLength(Result, Length(UsernameHash) + Length(PasswordHash));
        Move(UsernameHash[0], Result[0], Length(UsernameHash));
        Move(PasswordHash[0], Result[Length(UsernameHash)], Length(PasswordHash));

        Result := MD5Hash(Result);
      end;
    kvV2:
      begin
        // auth_hash = sha256(sha1(username) + sha1(password))
        UsernameHash := SHA1Hash(aUsername);
        PasswordHash := SHA1Hash(aPassword);

        SetLength(Result, Length(UsernameHash) + Length(PasswordHash));
        Move(UsernameHash[0], Result[0], Length(UsernameHash));
        Move(PasswordHash[0], Result[Length(UsernameHash)], Length(PasswordHash));

        Result := SHA256Hash(Result);
      end;
  end;
end;

type
  // Packed record for handshake1 response
  THandshake1Response = packed record
    RemoteSeed: array[0..15] of Byte;  // Adjust size as needed
    ServerHash: array[0..31] of Byte;  // Adjust size as needed
  end;

  // Packed record for authentication data
  TAuthData = packed record
    LocalSeed: array[0..15] of Byte;   // Adjust size as needed
    RemoteSeed: array[0..15] of Byte;  // Adjust size as needed
    AuthHash: array[0..31] of Byte;    // Adjust size as needed
  end;

  // Packed record for cipher data
  TCipherData = packed record
    Prefix: array[0..2] of Byte;
    LocalSeed: array[0..15] of Byte;   // Adjust size as needed
    RemoteSeed: array[0..15] of Byte;  // Adjust size as needed
    AuthHash: array[0..31] of Byte;    // Adjust size as needed
  end;

// Global variables
var
  _localSeed: array[0..15] of Byte;
  _remoteSeed: array[0..15] of Byte;
  _authHash: array[0..31] of Byte;

  _deviceIp: string;
  _session: record
    SessionStart: TDateTime;
    SessionId: array[0..255] of Char;
    SessionExpire: Integer;
    Key: array[0..31] of Byte;
    Sig: array[0..31] of Byte;
    IV: record
      Hash: array[0..31] of Byte;
      Seq: array[0..3] of Byte;
    end;
    Seq: Cardinal;
  end;

// CORRECTED Handshake function:
function TKasaKLAPClient.Handshake(var StatusText: string): Boolean;

    function Validate(KlapVersion: TKlapVersion; CredType, aUsername, aPassword: string; TheServerHash: TBytes; var ValidationData, AuthHash: TBytes): boolean;
    var
      HashToValidate: TBytes;
      AuthStart: integer;
    begin
      AuthHash := CalculateAuthHash(KlapVersion, aUsername, aPassword);
      if assigned(FKasaLogger) then FKasaLogger(self,format('Validate: %s credentials local auth hash: %s',[CredType, BytesToHex(AuthHash)]));

      AuthStart := length(ValidationData)-length(AuthHash); //Place authhash at the end of ValidationData
      FillChar(ValidationData[AuthStart], length(AuthHash), #0);
      Move(AuthHash[0], ValidationData[AuthStart], length(AuthHash)); // auth hash goes last
      if assigned(FKasaLogger) then FKasaLogger(self,format('Validate: ValidationData: %s',[BytesToHex(ValidationData)]));
      HashToValidate := SHA256Hash(ValidationData);
      if assigned(FKasaLogger) then FKasaLogger(self,format('Validate: Auth HashToValidate (local_seed_auth_hash): %s',[BytesToHex(HashToValidate)]));

      // Compare the locally-calculated hash with the server-generated hash
      result := CompareMem(@HashToValidate[0], @TheServerHash[0], Length(HashToValidate));
      if not result // Debug output
        then StatusText := StatusText + #13#10 + 'Hash validation failed for user="'+aUsername+'" - authentication rejected by server:'
        else StatusText := StatusText + #13#10 + 'Hash validation succeeded for user="'+aUsername+'!';
      StatusText := StatusText + #13#10 + '   AuthHash: ' + BytesToHex(AuthHash);
      StatusText := StatusText + #13#10 + '   Calculated: ' + BytesToHex(HashToValidate);
      StatusText := StatusText + #13#10 + '   Server sent: ' + BytesToHex(TheServerHash);
    end;


    function ValidateWithAltCredentials(KlapVersion: TKlapVersion; aPassword: string; TheServerHash: TBytes; var ValidationData, AuthHash: TBytes): boolean;
    var
      I: Integer;
      jsoCred: ISuperObject;
    begin
      result := false;

      if not Assigned(AltCredentials) or (AltCredentials.DataType <> stArray) then
        Exit;

      for I := 0 to AltCredentials.AsArray.Length - 1 do
      begin
        jsoCred := AltCredentials.AsArray[I];
        if jsoCred.s['password'] <> '?'
          then aPassword := jsoCred.s['password'];
        try
          aPassword := DecodeBase64(aPassword);
        except
          //Use as-is
        end;
        if Validate(KlapVersion, jsoCred.s['type'], jsoCred.s['userid'], aPassword, TheServerHash, ValidationData, AuthHash) then
        begin
          result := true;
          Break;
        end;
      end;
    end;

  procedure RawHeadersToNamedValues(Headers: TStrings);
  var
    I, iColon: Integer;
  begin
    for I := 0 to Headers.Count - 1 do
      begin
        iColon := Pos(':',Headers[I]);
        if iColon > 0
          then Headers[I] := Copy(Headers[I],1,iColon-1) + '=' + TrimLeft(Copy(Headers[I],iColon+1,MaxInt));
      end;
  end;

  procedure ProcessResponseHeaders(Headers: TStrings);
  var
    CookiesSL: TStringlist;
    I: Integer;
    CookieHeader: string;
    StartPos, EndPos: Integer;
  begin
    RawHeadersToNamedValues(Headers);

    // After handshake1 succeeds, debug ALL cookies being returned:
    if assigned(FKasaLogger) then
      begin
        FKasaLogger(self,'=== ALL COOKIES FROM HANDSHAKE1 ===');
        // Get the full Set-Cookie header(s)
        for I := 0 to Headers.Count - 1 do
        begin
          if Pos('Set-Cookie', Headers[I]) > 0 then
            FKasaLogger(self,'Cookie Header: ' + Headers[I]);
        end;
      end;

    // Extract session ID from cookies
    CookiesSL := TStringlist.Create;
    try
      CookiesSL.Delimiter := ';';
      CookiesSL.DelimitedText := Headers.Values['Set-Cookie'];
      FSessionID := CookiesSL.Values['TP_SESSIONID'];
      FTimeOut := CookiesSL.Values['TIMEOUT'];
      if FSessionID = '' then
      begin
        StatusText := 'No session ID received from server';
        Exit;
      end;
    finally
      CookiesSL.Free;
    end;
  end;

var
  Success: boolean;
  URL: string;
  RequestStream, ResponseStream: TMemoryStream;
  ResponseData: TBytes;
  CombinedSeed: TBytes;
  Cookie: TIdCookie;
  ServerHash: TBytes;
  ValidationData: TBytes;
  I: integer;
  UserHash, PassHash, Combined: TBytes;
  HTTPHelper: THTTPIOHandlerHelper;
  Headers,
  ResponseHeaders: TStringList;
  HexStr: ansistring;
  CombinedSeedHash: TBytes;
begin
  SetLength(FSessionKey,0);
  SetLength(FSessionKeyMD5,0);
  SetLength(FSessionKeySHA256,0);
  try //except
    RequestStream := TMemoryStream.Create;
    ResponseStream := TMemoryStream.Create;
    try
      // Stage 1: Send local seed
      Result := False;
      URL := Format('http://%s/app/handshake1', [FHost]);
      FLocalSeed := GenerateRandomBytes(16);
      RequestStream.WriteBuffer(FLocalSeed[0], Length(FLocalSeed));
      RequestStream.Position := 0;

      HTTPHelper := THTTPIOHandlerHelper.Create;
      try
        HTTPHelper.KasaLogger := KasaLogger;
        Headers := TStringList.Create;
        ResponseHeaders := TStringList.Create;
        try
          Headers.Add('Content-Type: application/octet-stream');
          Headers.Add('Accept: */*');
          Headers.Add('Accept-Encoding: gzip, deflate');
          Headers.Add('User-Agent: Python/3.13 aiohttp/3.12.13');
{$IFDEF UseProxy}
          HTTPHelper.SetProxy('localhost', 80, '', '');
{$ENDIF}
          HTTPHelper.SendRawHTTPRequest(URL, 0, 'POST', Headers, RequestStream, ResponseHeaders, ResponseStream);

          ProcessResponseHeaders(ResponseHeaders);
        finally
          Headers.Free;
          ResponseHeaders.Free;
        end;
      finally
        HTTPHelper.Free;
      end;

      // Validate response length (should be 48 bytes: 16 remote seed + 32 server hash)
      if ResponseStream.Size < 48 then
      begin
        StatusText := 'Invalid response length: ' + IntToStr(Length(ResponseData)) + ' (expected 48)';
        Exit;
      end;

      // Extract response data
      SetLength(ResponseData, ResponseStream.Size);
      ResponseStream.Position := 0;
      ResponseStream.ReadBuffer(ResponseData[0], ResponseStream.Size);

      // Extract remote seed (first 16 bytes)
      SetLength(FRemoteSeed, 16);
      Move(ResponseData[0], FRemoteSeed[0], 16);

      // Extract server hash (next 32 bytes)
      SetLength(ServerHash, 32);
      Move(ResponseData[16], ServerHash[0], 32);

      if assigned(FKasaLogger) then
        begin
          FKasaLogger(self,format('Server returned FRemoteSeed: %s',[BytesToHex(FRemoteSeed)]));
          FKasaLogger(self,format('Server returned ServerHash: %s.',[BytesToHex(ServerHash)]));
        end;

      case FKlapVersion of
        kvV1:
          begin
            // Calculate v1 validation hash. The server calculates: SHA256(local_seed + auth_hash)
            SetLength(ValidationData, 16 + 16); // total length for local_seed + auth_hash
            Move(FLocalSeed[0], ValidationData[0], 16); // local seed first
            //The Validate() function will fill in the last 32 bytes of ValidationData with a locally-generated auth_hash
          end;
        kvV2:
          begin
            // Calculate v2 validation hash. The server calculates: SHA256(local_seed + remote_seed + auth_hash)
            SetLength(ValidationData, 16 + 16 + 32); // total length for local_seed + remote seed + auth_hash
            Move(FLocalSeed[0], ValidationData[0], 16); // local seed first
            Move(FRemoteSeed[0], ValidationData[16], 16); // then remote seed
            //The Validate() function will fill in the last 32 bytes of ValidationData with a locally-generated auth_hash
          end;
      end;


      StatusText := '';
      Success := false;
      if (FUsername <> '') and (FPassword <> '')
        then Success := Validate(FKlapVersion, 'USER', FUsername, FPassword, ServerHash, ValidationData, FAuthHash); //First try user's login credentials
      if not Success
        then Success := ValidateWithAltCredentials(FKlapVersion, FPassword, ServerHash, ValidationData, FAuthHash);
      if not Success then
        begin
          StatusText := StatusText + #13#10 + 'None of the attempts validated!'#13#10;
          Exit;
        end;

        if assigned(FKasaLogger) then FKasaLogger(self,'AuthHash for successful handshake1 (hex): ' + BytesToHex(FAuthHash));
    finally
      RequestStream.Free;
      ResponseStream.Free;
    end;
  except
    on E: Exception do
    begin
      StatusText := StatusText + #13#10 + 'Unxepected error from Handshake-Stage 1: ' + E.Message;
      Result := False;
      exit;
    end;
  end;

  if assigned(FKasaLogger) then
    begin
      FKasaLogger(self,'=== HANDSHAKE2 DEBUG ===');
      FKasaLogger(self,Format('SessionID: %s', [FSessionID]));
      FKasaLogger(self,'LocalSeed (hex): ' + BytesToHex(FLocalSeed));
      FKasaLogger(self,Format('LocalSeed length: %d', [Length(FLocalSeed)]));
      FKasaLogger(self,'RemoteSeed (hex): ' + BytesToHex(FRemoteSeed));
      FKasaLogger(self,Format('RemoteSeed length: %d', [Length(FRemoteSeed)]));
      FKasaLogger(self,'AuthHash (hex): ' + BytesToHex(FAuthHash));
      FKasaLogger(self,Format('AuthHash length: %d', [Length(FAuthHash)]));
    end;

  case FKlapVersion of
    kvV1:
      begin
        // Calculate session key: SHA256(remote_seed + auth_hash)
        SetLength(CombinedSeed, Length(FRemoteSeed) + Length(FAuthHash));
        Move(FRemoteSeed[0], CombinedSeed[0], Length(FRemoteSeed));
        Move(FAuthHash[0], CombinedSeed[Length(FRemoteSeed)], Length(FAuthHash));
        CombinedSeedHash := MD5Hash(CombinedSeed);
      end;
    kvV2:
      begin
        // Calculate session key: SHA256(remote_seed + local_seed + auth_hash)
        SetLength(CombinedSeed, Length(FRemoteSeed) + Length(FLocalSeed) + Length(FAuthHash));
        Move(FRemoteSeed[0], CombinedSeed[0], Length(FRemoteSeed));
        Move(FLocalSeed[0], CombinedSeed[Length(FRemoteSeed)], Length(FLocalSeed));
        Move(FAuthHash[0], CombinedSeed[Length(FRemoteSeed) + Length(FLocalSeed)], Length(FAuthHash));
        CombinedSeedHash := SHA256Hash(CombinedSeed);
      end;
    kvV2_Alt:
      begin
        // Calculate session key: SHA256(local_seed + remote_seed + auth_hash)
        SetLength(CombinedSeed, Length(FLocalSeed) + Length(FRemoteSeed) + Length(FAuthHash));
        Move(FLocalSeed[0], CombinedSeed[0], Length(FLocalSeed));
        Move(FRemoteSeed[0], CombinedSeed[Length(FLocalSeed)], Length(FRemoteSeed));
        Move(FAuthHash[0], CombinedSeed[Length(FLocalSeed) + Length(FRemoteSeed)], Length(FAuthHash));
        CombinedSeedHash := SHA256Hash(CombinedSeed);
      end;
  end;

  if assigned(FKasaLogger) then
    begin
      FKasaLogger(self,'CombinedSeed (hex): ' + BytesToHex(CombinedSeed));
      FKasaLogger(self,Format('CombinedSeed total length: %d', [Length(CombinedSeed)]));
      FKasaLogger(self,'CombinedSeedHash (hex): ' + BytesToHex(CombinedSeedHash));
      FKasaLogger(self,Format('CombinedSeedHash total length: %d', [Length(CombinedSeedHash)]));
    end;

  URL := Format('http://%s/app/handshake2', [FHost]);
  try //except
    HTTPHelper := THTTPIOHandlerHelper.Create;
    try
      HTTPHelper.KasaLogger := KasaLogger;
      Headers := TStringList.Create;
      ResponseHeaders := TStringList.Create;
      RequestStream := TMemoryStream.Create;
      ResponseStream := TMemoryStream.Create;
      try
        Headers.Add('Content-Type: application/octet-stream');
        Headers.Add('Accept: */*');
        Headers.Add('Accept-Encoding: gzip, deflate');
        Headers.Add('Cookie: TP_SESSIONID=' + FSessionID); // + '; Max-Age=' + IntToStr(StrToInt(FTimeout)+1200) + '; Path=/');
        Headers.Add('User-Agent: Python/3.13 aiohttp/3.12.13');

        RequestStream.WriteBuffer(CombinedSeedHash[0], Length(CombinedSeedHash));
        RequestStream.Position := 0;
{$IFDEF UseProxy}
        HTTPHelper.SetProxy('localhost', 80, '', '');
{$ENDIF}
        HTTPHelper.SendRawHTTPRequest(URL, 0, 'POST', Headers, RequestStream, ResponseHeaders, ResponseStream);

        FSessionKeyMD5 := MD5Hash(CombinedSeed);
        FSessionKeySHA256 := SHA256Hash(CombinedSeed);
        Result := True;

        SetLength(ResponseData, ResponseStream.Size);
        ResponseStream.Position := 0;
        ResponseStream.ReadBuffer(ResponseData[0], ResponseStream.Size);

        if assigned(FKasaLogger) then
          begin
            FKasaLogger(self,'POST Response:');
            FKasaLogger(self,'ResponseData (hex): ' + BytesToHex(ResponseData));
          end;
      finally
        Headers.Free;
        ResponseHeaders.Free;
        RequestStream.Free;
        ResponseStream.Free;
      end;

    finally
      HTTPHelper.Free;
    end;

    // Initialize encryption parameters (call this after handshake)
    InitializeEncryption;
  except
    on E: Exception do
    begin
      StatusText := StatusText + #13#10 + 'Unxepected error from Handshake-Stage 2: ' + E.Message;
      Result := False;
    end;
  end;
end;

procedure TKasaKLAPClient.InitializeEncryption;
var
  KeyPayload, IVPayload, SigPayload: TBytes;
  FullIV: TBytes;
  TempSeq: LongWord;
begin
  // Key derivation: "lsk" + local_seed + remote_seed + user_hash
  SetLength(KeyPayload, 3 + Length(FLocalSeed) + Length(FRemoteSeed) + Length(FAuthHash));
  KeyPayload[0] := Ord('l');
  KeyPayload[1] := Ord('s');
  KeyPayload[2] := Ord('k');
  Move(FLocalSeed[0], KeyPayload[3], Length(FLocalSeed));
  Move(FRemoteSeed[0], KeyPayload[3 + Length(FLocalSeed)], Length(FRemoteSeed));
  Move(FAuthHash[0], KeyPayload[3 + Length(FLocalSeed) + Length(FRemoteSeed)], Length(FAuthHash));
  FEncryptionKey := SHA256Hash(KeyPayload);
  SetLength(FEncryptionKey, 16); // AES-128 key

  // IV derivation: "iv" + local_seed + remote_seed + user_hash
  SetLength(IVPayload, 2 + Length(FLocalSeed) + Length(FRemoteSeed) + Length(FAuthHash));
  IVPayload[0] := Ord('i');
  IVPayload[1] := Ord('v');
  Move(FLocalSeed[0], IVPayload[2], Length(FLocalSeed));
  Move(FRemoteSeed[0], IVPayload[2 + Length(FLocalSeed)], Length(FRemoteSeed));
  Move(FAuthHash[0], IVPayload[2 + Length(FLocalSeed) + Length(FRemoteSeed)], Length(FAuthHash));
  FullIV := SHA256Hash(IVPayload);

  // Base IV is first 12 bytes, sequence number from last 4 bytes (big-endian, signed)
  SetLength(FBaseIV, 12);
  Move(FullIV[0], FBaseIV[0], 12);
  // Convert last 4 bytes to signed 32-bit integer (big-endian)
  TempSeq := (FullIV[28] shl 24) or (FullIV[29] shl 16) or (FullIV[30] shl 8) or FullIV[31];
  FSeqNum := Integer(TempSeq); // Cast unsigned to signed

  // Signature key derivation: "ldk" + local_seed + remote_seed + user_hash
  SetLength(SigPayload, 3 + Length(FLocalSeed) + Length(FRemoteSeed) + Length(FAuthHash));
  SigPayload[0] := Ord('l');
  SigPayload[1] := Ord('d');
  SigPayload[2] := Ord('k');
  Move(FLocalSeed[0], SigPayload[3], Length(FLocalSeed));
  Move(FRemoteSeed[0], SigPayload[3 + Length(FLocalSeed)], Length(FRemoteSeed));
  Move(FAuthHash[0], SigPayload[3 + Length(FLocalSeed) + Length(FRemoteSeed)], Length(FAuthHash));
  FSignatureKey := SHA256Hash(SigPayload);
  SetLength(FSignatureKey, 28); // Take first 28 bytes
end;

function TKasaKLAPClient.PKCS7Pad(const Data: TBytes; BlockSize: Integer): TBytes;
var
  PadLength: Integer;
  i: Integer;
begin
  PadLength := BlockSize - (Length(Data) mod BlockSize);
  SetLength(Result, Length(Data) + PadLength);
  Move(Data[0], Result[0], Length(Data));
  for i := Length(Data) to Length(Result) - 1 do
    Result[i] := PadLength;
end;

function TKasaKLAPClient.PKCS7Unpad(const Data: TBytes): TBytes;
var
  PadLength: Integer;
begin
  if Length(Data) = 0 then
  begin
    SetLength(Result, 0);
    Exit;
  end;

  PadLength := Data[Length(Data) - 1];
  if (PadLength > Length(Data)) or (PadLength = 0) then
    raise Exception.Create('Invalid PKCS7 padding');

  SetLength(Result, Length(Data) - PadLength);
  Move(Data[0], Result[0], Length(Result));
end;

function TKasaKLAPClient.KlapEncrypt(const APlaintext: TBytes): TBytes;
var
  IV: TBytes;
  PaddedData: TBytes;
  CipherText: TBytes;
  SeqBytes: TBytes;
  SigPayload: TBytes;
  Signature: TBytes;
begin
  // Increment sequence number BEFORE encryption
  Inc(FSeqNum);

  // Create IV: base_iv + sequence_number (big-endian)
  SetLength(IV, 16);
  Move(FBaseIV[0], IV[0], 12);
  IV[12] := (FSeqNum shr 24) and $FF;
  IV[13] := (FSeqNum shr 16) and $FF;
  IV[14] := (FSeqNum shr 8) and $FF;
  IV[15] := FSeqNum and $FF;

  // Add PKCS7 padding
  PaddedData := PKCS7Pad(APlaintext, 16);

  // Encrypt with AES-CBC
  CipherText := AESEncryptCBC(PaddedData, FEncryptionKey, IV);

  // Create signature: SHA256(sig_key + seq_num + ciphertext)
  SetLength(SeqBytes, 4);
  SeqBytes[0] := (FSeqNum shr 24) and $FF;
  SeqBytes[1] := (FSeqNum shr 16) and $FF;
  SeqBytes[2] := (FSeqNum shr 8) and $FF;
  SeqBytes[3] := FSeqNum and $FF;

  SetLength(SigPayload, Length(FSignatureKey) + 4 + Length(CipherText));
  Move(FSignatureKey[0], SigPayload[0], Length(FSignatureKey));
  Move(SeqBytes[0], SigPayload[Length(FSignatureKey)], 4);
  Move(CipherText[0], SigPayload[Length(FSignatureKey) + 4], Length(CipherText));

  Signature := SHA256Hash(SigPayload);

  // Return signature + ciphertext
  SetLength(Result, Length(Signature) + Length(CipherText));
  Move(Signature[0], Result[0], Length(Signature));
  Move(CipherText[0], Result[Length(Signature)], Length(CipherText));
end;

function TKasaKLAPClient.KlapDecrypt(const AEncryptedData: TBytes): TBytes;
var
  CipherText: TBytes;
  DecryptedData: TBytes;
  IV: TBytes;
begin
  // Skip first 32 bytes (signature) and decrypt the rest
  SetLength(CipherText, Length(AEncryptedData) - 32);
  Move(AEncryptedData[32], CipherText[0], Length(CipherText));

  // Create IV for decryption
  SetLength(IV, 16);
  Move(FBaseIV[0], IV[0], 12);
  IV[12] := (FSeqNum shr 24) and $FF;
  IV[13] := (FSeqNum shr 16) and $FF;
  IV[14] := (FSeqNum shr 8) and $FF;
  IV[15] := FSeqNum and $FF;

  // Decrypt
  DecryptedData := AESDecryptCBC(CipherText, FEncryptionKey, IV);

  // Remove PKCS7 padding
  Result := PKCS7Unpad(DecryptedData);
end;

function TKasaKLAPClient.SendCommand(ACommand: string; var Res: string): boolean;
var
  CombinedSeed: TBytes;
  CombinedSeedHash: TBytes;
  URL: string;
  RequestStream: TMemoryStream;
  ResponseStream: TMemoryStream;
  PlaintextData, EncryptedData, DecryptedData: TBytes;
  Cookie: TIdCookie;
  StatusText: string;
  IdCookieMgr: TIdCookieManager;
  HTTPHelper: THTTPIOHandlerHelper;
  Headers,
  ResponseHeaders: TStringList;
begin
  Result := false;
  StatusText := '';

  if FSessionID = '' then
    if not Handshake(Res)
      then Exit;

  if assigned(FKasaLogger) then
    begin
      FKasaLogger(self,'');
      FKasaLogger(self,'=== SEND COMMAND ===');
      FKasaLogger(self,Format('SessionID: %s', [FSessionID]));
      FKasaLogger(self,'LocalSeed (hex): ' + BytesToHex(FLocalSeed));
    end;

  PlaintextData := TEncoding.UTF8.GetBytes(ACommand); //Ascii ?
  EncryptedData := KlapEncrypt(PlaintextData{, FSeqNum});

  URL := Format('http://%s/app/request', [FHost]);

  RequestStream := TMemoryStream.Create;
  ResponseStream := TMemoryStream.Create;
  try
    RequestStream.WriteBuffer(EncryptedData[0], Length(EncryptedData));
    RequestStream.Position := 0;

    HTTPHelper := THTTPIOHandlerHelper.Create;
    try
      Headers := TStringList.Create;
      ResponseHeaders := TStringList.Create;
      try
        Headers.Add('Content-Type: application/octet-stream');
        Headers.Add('Accept: */*');
        Headers.Add('Accept-Encoding: gzip, deflate');
        Headers.Add('Cookie: TP_SESSIONID=' + FSessionID); // + '; Max-Age=' + IntToStr(StrToInt(FTimeout)+1200) + '; Path=/');
        Headers.Add('User-Agent: Python/3.13 aiohttp/3.12.13');
  {$IFDEF UseProxy}
        HTTPHelper.SetProxy('localhost', 80, '', '');
  {$ENDIF}
        HTTPHelper.SendRawHTTPRequest(URL, FSeqNum, 'POST', Headers, RequestStream, ResponseHeaders, ResponseStream);

        ResponseStream.Position := 0;
        SetLength(DecryptedData, ResponseStream.Size);
        ResponseStream.ReadBuffer(DecryptedData[0], ResponseStream.Size);

        DecryptedData := KlapDecrypt(DecryptedData{, FSeqNum});
        Res := TEncoding.UTF8.GetString(DecryptedData);
        result := true;
      finally
        Headers.Free;
        ResponseHeaders.Free;
      end;
    finally
      HTTPHelper.Free;
    end;

  finally
    RequestStream.Free;
    ResponseStream.Free;
  end;
  try
  except
    on E: Exception do
    begin
      StatusText := StatusText + #13#10 + 'Unxepected error from SendCommand: ' + E.Message;
    end;
  end;
end;

function TKasaKLAPClient.PerformSend(Command: string): Boolean;
var
  Response: string;
begin
  if SendCommand(Command, Response) then
    begin
      case FKlapVersion of
        kvV1:
          Result := Pos('"err_code":0', Response) > 0;
        kvV2, kvV2_alt:
          Result := (Pos('"error_code":0', Response) > 0) or (Pos('"result":', Response) > 0);
      end;
    end
   else Result := false;
end;

function TKasaKLAPClient.TurnOn: Boolean;
var
  Command: string;
begin
  case FKlapVersion of
    kvV1:
      Command := '{"system":{"set_relay_state":{"state":1}}}';
    kvV2, kvV2_alt:
      Command := '{"method":"set_device_info","params":{"device_on":true}}';
  end;

  result := PerformSend(Command);
end;

function TKasaKLAPClient.TurnOff: Boolean;
var
  Command: string;
  Response: string;
begin
  case FKlapVersion of
    kvV1:
      Command := '{"system":{"set_relay_state":{"state":0}}}';
    kvV2, kvV2_alt:
      Command := '{"method":"set_device_info","params":{"device_on":false}}';
  end;

  result := PerformSend(Command);
end;

function TKasaKLAPClient.GetDeviceInfo(var Res: string): boolean;
var
  Command: string;
begin
  case FKlapVersion of
    kvV1:
      Command := '{"system":{"get_sysinfo":{}}}';
    kvV2, kvV2_alt:
      Command := '{"method":"get_device_info","params":null}';
  end;

  result := SendCommand(Command, Res);
end;

end.
