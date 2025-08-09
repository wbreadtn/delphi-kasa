unit KasaXORController;

interface

uses
  System.SysUtils, System.Classes, System.JSON, System.NetEncoding,
  IdTCPClient, IdExceptionCore, IdException, IdGlobal;

type
  TKasaDeviceInfo = record
    DeviceId: string;
    Model: string;
    HardwareVersion: string;
    SoftwareVersion: string;
    DeviceName: string;
    IsOn: Boolean;
    RSSI: Integer;
    LEDOff: Boolean;
  end;

  TKasaXORController = class
  private
    FHost: string;
    FPort: Integer;
    FTimeout: Integer;

    function EncryptKasaMessage(const Message: string): TBytes;
    function DecryptKasaMessage(const Data: TBytes): string;
    function DecryptKasaMessageDirect(const Data: TBytes; var Key: Byte): string;
    function SendCommand(const Command: string): string;
    function CreateSystemCommand: string;
    function CreateRelayCommand(State: Boolean): string;

  public
    constructor Create(const Host: string; Port: Integer = 9999; Timeout: Integer = 5000);

    // Main control methods
    function TurnOn: Boolean;
    function TurnOff: Boolean;
    function Toggle: Boolean;
    function GetState: Boolean;

    // Device information
    function GetDeviceInfo(var Res: TKasaDeviceInfo): boolean;
    function GetSystemInfo: string;

    // LED control
    function SetLED(LedOn: Boolean): Boolean;

    // Properties
    property Host: string read FHost write FHost;
    property Port: Integer read FPort write FPort;
    property Timeout: Integer read FTimeout write FTimeout;
  end;

implementation

constructor TKasaXORController.Create(const Host: string; Port: Integer = 9999; Timeout: Integer = 5000);
begin
  inherited Create;
  FHost := Host;
  FPort := Port;
  FTimeout := Timeout;
end;

function TKasaXORController.EncryptKasaMessage(const Message: string): TBytes;
var
  Key, i: Byte;
  MessageBytes: TBytes;
  EncryptedData: TBytes;
begin
  // TP-Link Kasa encryption using XOR with rolling key
  MessageBytes := TEncoding.UTF8.GetBytes(Message);
  SetLength(EncryptedData, Length(MessageBytes) + 4);

  // Add length header (big-endian)
  EncryptedData[0] := (Length(MessageBytes) shr 24) and $FF;
  EncryptedData[1] := (Length(MessageBytes) shr 16) and $FF;
  EncryptedData[2] := (Length(MessageBytes) shr 8) and $FF;
  EncryptedData[3] := Length(MessageBytes) and $FF;

  Key := $AB; // Initial XOR key
  for i := 0 to Length(MessageBytes) - 1 do
  begin
    EncryptedData[i + 4] := MessageBytes[i] xor Key;
    Key := EncryptedData[i + 4];
  end;

  Result := EncryptedData;
end;

function TKasaXORController.DecryptKasaMessage(const Data: TBytes): string;
var
  Key, i: Byte;
  DecryptedBytes: TBytes;
  DataLength: Integer;
begin
  if Length(Data) < 4 then
    Exit('');

  // Extract length from header
  DataLength := (Data[0] shl 24) or (Data[1] shl 16) or (Data[2] shl 8) or Data[3];

  if Length(Data) < DataLength + 4 then
    Exit('');

  SetLength(DecryptedBytes, DataLength);
  Key := $AB; // Initial XOR key

  for i := 0 to DataLength - 1 do
  begin
    DecryptedBytes[i] := Data[i + 4] xor Key;
    Key := Data[i + 4];
  end;

  Result := TEncoding.UTF8.GetString(DecryptedBytes);
end;

function TKasaXORController.DecryptKasaMessageDirect(const Data: TBytes; var Key: Byte): string;
var
  i: Byte;
  DecryptedBytes: TBytes;
  TempResult: string;
  BraceCount: Integer;
  ActualLength: Integer;
begin
  if Length(Data) = 0 then
    Exit('');

  SetLength(DecryptedBytes, Length(Data));

  for i := 0 to Length(Data) - 1 do
  begin
    DecryptedBytes[i] := Data[i] xor Key;
    Key := Data[i];
  end;

  // Convert to string first
  //TempResult := TEncoding.UTF8.GetString(DecryptedBytes);
  TempResult := TEncoding.Ansi.GetString(DecryptedBytes);
  //TempResult := TEncoding.Ascii.GetString(DecryptedBytes);

  // Find the end of the JSON by counting braces
  BraceCount := 0;
  ActualLength := 0;

  for i := 1 to Length(TempResult) do
  begin
    case TempResult[i] of
      #0:
      begin
        ActualLength := i-1;
        Break;
      end;
    end;
  end;

  // Return only the complete JSON
  if ActualLength > 0 then
    Result := Copy(TempResult, 1, ActualLength-1)
  else
    Result := TempResult; // Fallback if brace counting fails
end;

function TKasaXORController.SendCommand(const Command: string): string;
var
  TCPClient: TIdTCPClient;
  EncryptedData: TBytes;
  ResponseLength: Integer;
  LengthHeader: TBytes;
  MessageDataBuf: TBytes;
  MessageData: TBytes;
  BytePos,BytesToRead: integer;
  Key: Byte;
  I: Integer;
begin
  Result := '';
  TCPClient := TIdTCPClient.Create(nil);
  try
    TCPClient.Host := FHost;
    TCPClient.Port := FPort;
    TCPClient.ConnectTimeout := FTimeout;
    TCPClient.ReadTimeout := FTimeout;

    try
      TCPClient.Connect;

      // Encrypt and send command
      EncryptedData := EncryptKasaMessage(Command);
      TCPClient.IOHandler.Write(TIdBytes(EncryptedData));

      // Read response
      // First read the 4-byte length header
      SetLength(LengthHeader, 4);
      TCPClient.IOHandler.ReadBytes(TIdBytes(LengthHeader), 4, False);

      // Calculate response length from header
      ResponseLength := (LengthHeader[0] shl 24) or (LengthHeader[1] shl 16) or
                       (LengthHeader[2] shl 8) or LengthHeader[3];

      // Read the encrypted message data
      SetLength(MessageDataBuf, ResponseLength);
      SetLength(MessageData, ResponseLength);
      //TCPClient.IOHandler.ReadBytes(TIdBytes(MessageData), ResponseLength, False);
      //TCPClient.IOHandler.ReadBytes(TIdBytes(MessageData), ResponseLength, False);

      BytesToRead := 1;
      BytePos := 0;
      Key := $AB; // Initial XOR key

      Result := '';
      for I := 1 to ResponseLength do
        begin
          TCPClient.IOHandler.ReadBytes(TIdBytes(MessageDataBuf), BytesToRead, False);
          Result := Result + DecryptKasaMessageDirect(MessageDataBuf, Key);
          Move(MessageDataBuf[0], MessageData[BytePos], BytesToRead);
          Inc(BytePos, BytesToRead);
          Key := MessageData[BytePos-1];
        end;

      // Decrypt directly from the message data (without reconstructing header)
      //Result := DecryptKasaMessageDirect(MessageData);

    except
      on E: Exception do
        raise Exception.Create('Communication error: ' + E.Message);
    end;

  finally
    if TCPClient.Connected then
      TCPClient.Disconnect;
    TCPClient.Free;
  end;
end;

function TKasaXORController.CreateSystemCommand: string;
begin
  Result := '{"system":{"get_sysinfo":null}}';
end;

function TKasaXORController.CreateRelayCommand(State: Boolean): string;
begin
  if State then
    Result := '{"system":{"set_relay_state":{"state":1}}}'
  else
    Result := '{"system":{"set_relay_state":{"state":0}}}';
end;

function TKasaXORController.TurnOn: Boolean;
var
  Response: string;
  JSONResponse: TJSONObject;
  SystemObj: TJSONObject;
  RelayObj: TJSONObject;
begin
  Result := False;
  try
    Response := SendCommand(CreateRelayCommand(True));
    JSONResponse := TJSONObject.ParseJSONValue(Response) as TJSONObject;
    try
      if Assigned(JSONResponse) then
      begin
        SystemObj := JSONResponse.GetValue('system') as TJSONObject;
        if Assigned(SystemObj) then
        begin
          RelayObj := SystemObj.GetValue('set_relay_state') as TJSONObject;
          if Assigned(RelayObj) then
          begin
            Result := (RelayObj.GetValue('err_code') as TJSONNumber).AsInt = 0;
          end;
        end;
      end;
    finally
      JSONResponse.Free;
    end;
  except
    on E: Exception do
      raise Exception.Create('Failed to turn on device: ' + E.Message);
  end;
end;

function TKasaXORController.TurnOff: Boolean;
var
  Response: string;
  JSONResponse: TJSONObject;
  SystemObj: TJSONObject;
  RelayObj: TJSONObject;
begin
  Result := False;
  try
    Response := SendCommand(CreateRelayCommand(False));
    JSONResponse := TJSONObject.ParseJSONValue(Response) as TJSONObject;
    try
      if Assigned(JSONResponse) then
      begin
        SystemObj := JSONResponse.GetValue('system') as TJSONObject;
        if Assigned(SystemObj) then
        begin
          RelayObj := SystemObj.GetValue('set_relay_state') as TJSONObject;
          if Assigned(RelayObj) then
          begin
            Result := (RelayObj.GetValue('err_code') as TJSONNumber).AsInt = 0;
          end;
        end;
      end;
    finally
      JSONResponse.Free;
    end;
  except
    on E: Exception do
      raise Exception.Create('Failed to turn off device: ' + E.Message);
  end;
end;

function TKasaXORController.Toggle: Boolean;
begin
  if GetState then
    Result := TurnOff
  else
    Result := TurnOn;
end;

function TKasaXORController.GetState: Boolean;
var
  DeviceInfo: TKasaDeviceInfo;
begin
  GetDeviceInfo(DeviceInfo);
  Result := DeviceInfo.IsOn;
end;

function TKasaXORController.GetDeviceInfo(var Res: TKasaDeviceInfo): boolean;
var
  Response: string;
  JSONResponse: TJSONObject;
  SystemObj: TJSONObject;
  SysInfoObj: TJSONObject;
begin
  result := false;
  FillChar(Result, SizeOf(Result), 0);

  try
    Response := SendCommand(CreateSystemCommand);
    JSONResponse := TJSONObject.ParseJSONValue(Response) as TJSONObject;
    try
      if Assigned(JSONResponse) then
      begin
        SystemObj := JSONResponse.GetValue('system') as TJSONObject;
        if Assigned(SystemObj) then
        begin
          SysInfoObj := SystemObj.GetValue('get_sysinfo') as TJSONObject;
          if Assigned(SysInfoObj) then
          begin
            Res.DeviceId := (SysInfoObj.GetValue('deviceId') as TJSONString).Value;
            Res.Model := (SysInfoObj.GetValue('model') as TJSONString).Value;
            Res.HardwareVersion := (SysInfoObj.GetValue('hw_ver') as TJSONString).Value;
            Res.SoftwareVersion := (SysInfoObj.GetValue('sw_ver') as TJSONString).Value;
            Res.DeviceName := (SysInfoObj.GetValue('alias') as TJSONString).Value;
            Res.IsOn := (SysInfoObj.GetValue('relay_state') as TJSONNumber).AsInt = 1;
            Res.RSSI := (SysInfoObj.GetValue('rssi') as TJSONNumber).AsInt;
            Res.LEDOff := (SysInfoObj.GetValue('led_off') as TJSONNumber).AsInt = 1;
            result := true;
          end;
        end;
      end;
    finally
      JSONResponse.Free;
    end;
  except
    on E: Exception do
      raise Exception.Create('Failed to get device info: ' + E.Message);
  end;
end;

function TKasaXORController.GetSystemInfo: string;
begin
  try
    Result := SendCommand(CreateSystemCommand);
  except
    on E: Exception do
      raise Exception.Create('Failed to get system info: ' + E.Message);
  end;
end;

function TKasaXORController.SetLED(LedOn: Boolean): Boolean;
var
  Command: string;
  Response: string;
  JSONResponse: TJSONObject;
  SystemObj: TJSONObject;
  LedObj: TJSONObject;
begin
  Result := False;

  if LedOn then
    Command := '{"system":{"set_led_off":{"off":0}}}'
  else
    Command := '{"system":{"set_led_off":{"off":1}}}';

  try
    Response := SendCommand(Command);
    JSONResponse := TJSONObject.ParseJSONValue(Response) as TJSONObject;
    try
      if Assigned(JSONResponse) then
      begin
        SystemObj := JSONResponse.GetValue('system') as TJSONObject;
        if Assigned(SystemObj) then
        begin
          LedObj := SystemObj.GetValue('set_led_off') as TJSONObject;
          if Assigned(LedObj) then
          begin
            Result := (LedObj.GetValue('err_code') as TJSONNumber).AsInt = 0;
          end;
        end;
      end;
    finally
      JSONResponse.Free;
    end;
  except
    on E: Exception do
      raise Exception.Create('Failed to set LED state: ' + E.Message);
  end;
end;

end.
