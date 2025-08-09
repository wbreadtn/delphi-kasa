program DemonstrateKasa;

{$APPTYPE CONSOLE}

uses
  Classes,
  System.SysUtils,
  KasaKLAPController,
  KasaXORController,
  IOUtils,
  Superobject
  ,RegularExpressions
  ,IdTCPClient
  ;

const
  TimeBetweenActions = 2000;

type
  TDemo = class(TObject)
  private
    FDoLog: boolean;
    constructor Create;
    procedure TestConnection(Host: string; Port: Integer);
    function TestHostAndPort(Host: string; Port: Integer): Boolean;
    function ScanPorts(Host: string): string;
    procedure Logger(Sender: TObject; Text: string);
    procedure Help;
    procedure DemonstrateXORControl(IP: string; Port: Integer);
    procedure DemonstrateKLAPControl(IP: string; Port: integer; CredsFileName: string; User, Pw: string);
    property DoLog: boolean read FDoLog write FDoLog;
  end;

constructor TDemo.Create;
begin
  inherited;
  FDoLog := False;
end;

procedure TDemo.Logger(Sender: TObject; Text: string);
begin
  if FDoLog
    then WriteLn(text);
end;

function TDemo.TestHostAndPort(Host: string; Port: Integer): Boolean;
var
  TCPClient: TIdTCPClient;
begin
  Result := False;
  TCPClient := TIdTCPClient.Create(nil);
  try
    TCPClient.Host := Host;
    TCPClient.Port := Port;
    TCPClient.ConnectTimeout := 5000;

    try
      TCPClient.Connect;
      Result := TCPClient.Connected;
      if TCPClient.Connected then
        TCPClient.Disconnect;
    except
      // Connection failed
      Result := False;
    end;
  finally
    TCPClient.Free;
  end;
end;

function TDemo.ScanPorts(Host: string): string;
var
  TCPClient: TIdTCPClient;
  TestPorts: array[0..6] of Integer;
  i: Integer;
  PortResult: string;
begin
  Result := 'Port scan results for ' + Host + ':' + sLineBreak;
  TestPorts[0] := 9999;  // Standard Kasa port
  TestPorts[1] := 80;    // HTTP
  TestPorts[2] := 443;   // HTTPS
  TestPorts[3] := 23;    // Telnet
  TestPorts[4] := 9998;  // Alternative Kasa port
  TestPorts[5] := 1040;  // Some TP-Link devices
  TestPorts[6] := 20002; // Some newer devices

  for i := 0 to High(TestPorts) do
  begin
    TCPClient := TIdTCPClient.Create(nil);
    try
      TCPClient.Host := Host;
      TCPClient.Port := TestPorts[i];
      TCPClient.ConnectTimeout := 2000; // Shorter timeout for scanning

      try
        TCPClient.Connect;
        if TCPClient.Connected then
        begin
          PortResult := 'OPEN';
          TCPClient.Disconnect;
        end
        else
          PortResult := 'CLOSED';
      except
        PortResult := 'CLOSED/FILTERED';
      end;

      Result := Result + Format('Port %d: %s', [TestPorts[i], PortResult]) + sLineBreak;
    finally
      TCPClient.Free;
    end;
  end;
end;

procedure TDemo.TestConnection(Host: string; Port: Integer);
begin
  // First, test basic connectivity
  WriteLn('Testing connection to ', Host, ':', Port, '...');
  if TestHostAndPort(Host, Port) then
  begin
    WriteLn('Connection successful!');
  end
  else
  begin
    WriteLn('Error - Connection failed!');
    WriteLn('Running port scan...');
    WriteLn(ScanPorts(Host));
    WriteLn('Troubleshooting tips:');
    WriteLn('1. Verify the IP address is correct');
    WriteLn('2. Ensure device is powered on and connected to WiFi');
    WriteLn('3. Check if you can ping the device');
    WriteLn('4. Try using the Kasa app to confirm device is online');
    WriteLn('5. Check firewall settings');
    Exit;
  end;
end;

procedure TDemo.Help;
begin
  WriteLn('Help:');
  WriteLn('  Typical ports for older XOR devices are 9999, 9998, 1040 and 20002');
  WriteLn('  Typical port for newer KLAP devices is 80');
end;

procedure TDemo.DemonstrateXORControl(IP: string; Port: Integer);
var
  HSDevice: TKasaXORController;
  DeviceInfo: TKasaDeviceInfo;
  CurrentState: Boolean;
  st: string;
begin
  HSDevice := TKasaXORController.Create(IP, Port);
  try
    try
      // Get device information
      WriteLn('Getting device information...');
      if not HSDevice.GetDeviceInfo(DeviceInfo) then
        begin
          Writeln('GetDeviceInfo failed!');
          exit;
        end;

      WriteLn('Device ID: ', DeviceInfo.DeviceId);
      WriteLn('Model: ', DeviceInfo.Model);
      WriteLn('Hardware Version: ', DeviceInfo.HardwareVersion);
      WriteLn('Software Version: ', DeviceInfo.SoftwareVersion);
      WriteLn('Device Name: ', DeviceInfo.DeviceName);
      WriteLn('Current State: ', BoolToStr(DeviceInfo.IsOn, True));
      WriteLn('RSSI: ', DeviceInfo.RSSI, ' dBm');
      WriteLn('LED Off: ', BoolToStr(DeviceInfo.LEDOff, True));
      WriteLn;

      // Check current state
      CurrentState := HSDevice.GetState;
      WriteLn('Current switch state: ', BoolToStr(CurrentState, True));
      WriteLn;

      // Turn on the switch
      WriteLn('Turning switch ON...');
      if HSDevice.TurnOn then
        WriteLn('Switch turned ON successfully')
      else
        WriteLn('Failed to turn switch ON');
      Sleep(TimeBetweenActions);
      WriteLn;

      // Check state after turning on
      CurrentState := HSDevice.GetState;
      WriteLn('State after turning ON: ', BoolToStr(CurrentState, True));
      WriteLn;

      // Turn off the switch
      WriteLn('Turning switch OFF...');
      if HSDevice.TurnOff then
        WriteLn('Switch turned OFF successfully')
      else
        WriteLn('Failed to turn switch OFF');
      Sleep(TimeBetweenActions);
      WriteLn;

      // Check state after turning off
      CurrentState := HSDevice.GetState;
      WriteLn('State after turning OFF: ', BoolToStr(CurrentState, True));
      WriteLn;
      (*
      // Toggle the switch
      WriteLn('Toggling switch...');
      if HSDevice.Toggle then
        WriteLn('Switch toggled successfully')
      else
        WriteLn('Failed to toggle switch');
      Sleep(TimeBetweenActions);
      WriteLn;
      *)
      // Final state check
      CurrentState := HSDevice.GetState;
      WriteLn('Final state: ', BoolToStr(CurrentState, True));
      WriteLn;

      (*
      // LED control demo
      WriteLn('Turning LED OFF...');
      if HSDevice.SetLED(False) then
        WriteLn('LED turned OFF successfully')
      else
        WriteLn('Failed to turn LED OFF');
      Sleep(TimeBetweenActions);

      WriteLn('Turning LED ON...');
      if HSDevice.SetLED(True) then
        WriteLn('LED turned ON successfully')
      else
        WriteLn('Failed to turn LED ON');
      WriteLn;
      *)

      // Display raw system info
      WriteLn('Raw system information:');
      st := HSDevice.GetSystemInfo;
      WriteLn(st);
      WriteLn;

    except
      on E: Exception do
        WriteLn('Error: ', E.Message);
    end;

  finally
    HSDevice.Free;
  end;
end;

procedure TDemo.DemonstrateKLAPControl(IP: string; Port: integer; CredsFileName: string; User, Pw: string);
var
  KasaClient: TKasaKLAPClient;
  DeviceInfo: string;
begin
 KasaClient := TKasaKLAPClient.Create(IP, Port, User, Pw);
  try
    KasaClient.KasaLogger := Logger;
    KasaClient.KlapVersion := kvV2;
    if CredsFileName = ''
      then CredsFileName := ExtractFilePath(ParamStr(0))+'kasa_cred.json';
    if not FileExists(CredsFileName) then
       begin
         Writeln(format('File %s not found.',[CredsFileName]));
         exit;
       end;
    KasaClient.AltCredentials := SO(TFile.ReadAllText(CredsFileName));

    // Get device information
    WriteLn('Get info');
    if not KasaClient.GetDeviceInfo(DeviceInfo) then
       begin
         Writeln('Error from Device Info: ', DeviceInfo);
         exit;
       end;
    Writeln('Device Info: ', DeviceInfo);
    Sleep(TimeBetweenActions);

     // Turn on the switch
    WriteLn('Turn it on');
    if KasaClient.TurnOn then
       Writeln('Switch turned ON')
      else
       Writeln('Failed to turn switch ON');
    Sleep(TimeBetweenActions);

    // Turn off the switch
    WriteLn('Turn it off');
    if KasaClient.TurnOff then
       Writeln('Switch turned OFF')
      else
       Writeln('Failed to turn switch OFF');
  finally
    KasaClient.Free;
  end;

end;

procedure ParseInTwo(const S, MidStr: String; var ItemName, ItemValue: String);
begin
  If Pos(MidStr, S) > 0 Then
    begin
      ItemName := Copy(S, 1, Pos(MidStr,S)-1);
      ItemValue := Copy(S, Length(ItemName)+Length(MidStr)+1, 32767);
    end
   else
    begin
      ItemName := S;
      ItemValue := '';
    end;
end;

function BoolToString(b: boolean; const TrueS, FalseS: string): String;
begin
  if b then
      result := TrueS
    else result := FalseS;
end;

function GetHostAndPort(var Host: string; var Port: Integer; DefaultHost: string = ''; DefaultPort: Integer = -1): boolean;
var
  st: string;
begin
  if DefaultHost <> '' then
    begin
      Write(format('Enter target Host/IP address (default is %s): ',[DefaultHost]));
      ReadLn(Host);
      if Host = ''
        then Host := DefaultHost;
    end
    else if Host = '' then
    begin
      Write('Enter target Host/IP address: ');
      ReadLn(Host);
    end;

  if DefaultPort <> -1 then
    begin
      Write(format('Enter Port (default is %d): ',[DefaultPort]));
      ReadLn(st);
      Port := StrToIntDef(st,DefaultPort);
    end
   else if Port = -1 then
    begin
      Write('Enter Port: ');
      ReadLn(st);
      Port := StrToIntDef(st,-1);
    end;
end;

var
  CredsFile,
  Host,
  st: string;
  Choice,
  Port: Integer;
  Demo: TDemo;
begin
  Host := '';
  Port := -1;
  CredsFile := '';
  if paramStr(1) <> ''
    then Host := paramStr(1);
  if Pos(':',Host) > 0 then
    begin
      ParseInTwo(Host, ':', Host, st);
      Port := StrToIntDef(st,-1);
    end;
  if paramStr(2) <> ''
    then CredsFile := paramStr(2);

  Demo := TDemo.Create;
  try
    Demo.DoLog := false;
    try
      repeat
        WriteLn(format('Make a selection (Host=%s, Port=%s):',[BoolToString(Host<>'',Host,'unassigned'),BoolToString(Port<>-1,IntToStr(Port),'unassigned')]));
        WriteLn('  ? - Help');
        WriteLn('  L - Toggle logger on/off');
        WriteLn('  0 - Enter Host and Port');
        WriteLn('  1 - Test connection');
        WriteLn('  2 - Demo XOR device communication '+BoolToString((Port<>-1) and (Port<>80),'(reccommended)',''));
        WriteLn('  3 - Demo KLAP device communication '+BoolToString(Port=80,'(reccommended)',''));
        WriteLn('  Else exit.');
        Write('Choice: ');
        ReadLn(st);
        if st = '?' then
          begin
            WriteLn;
            Demo.Help;
            WriteLn;
            continue;
          end;
        if SameText(st,'L') then
          begin
            WriteLn;
            Demo.DoLog := not Demo.DoLog;
            WriteLn('Logger is now '+BoolToString(Demo.DoLog,'ON','OFF'));
            WriteLn;
            continue;
          end;
        Choice := StrToIntDef(st,-1);
        if Choice in [1,2,3] then
          repeat
            WriteLn;
            GetHostAndPort(Host,Port);
            WriteLn;
          until (Host <> '') and (Port <> -1);
        case Choice of
          0: begin
               WriteLn;
               GetHostAndPort(Host,Port,Host,Port);
               WriteLn;
             end;
          1: begin
               WriteLn;
               Demo.TestConnection(Host, Port);
               WriteLn;
             end;
          2: begin
               WriteLn;
               WriteLn(format('Using classic XOR protocol to contact device at Host=%s, Port=%d ...',[Host,Port]));
               Demo.DemonstrateXORControl(Host, Port);
               WriteLn;
             end;
          3: begin
               WriteLn;
               WriteLn(format('Using KLAP protocol to contact device at Host=%s, Port=%d ...',[Host,Port]));
               Demo.DemonstrateKLAPControl(Host, Port, CredsFile, '', '');
               WriteLn;
             end;
        end;
      until not Choice in [0,1,2,3];
      WriteLn;
      WriteLn('Exiting... Goodbye.');
    except
      on E: Exception do
        WriteLn('Application error: ', E.ClassName, ': ', E.Message);
    end;
  finally
    Demo.Free;
  end;

end.


