unit Main;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  Menus, StdCtrls, wcrypt2, crypto;

type
  TMainForm = class(TForm)
    MainMenu1: TMainMenu;
    mFile: TMemo;
    FileItem: TMenuItem;
    OpenItem: TMenuItem;
    EncryptItem: TMenuItem;
    DecryptItem: TMenuItem;
    SaveItem: TMenuItem;
    ExitItem: TMenuItem;
    OpenDialog1: TOpenDialog;
    SaveDialog1: TSaveDialog;
    CloseItem: TMenuItem;
    Clear: TMenuItem;
    About1: TMenuItem;
    Autor1: TMenuItem;
    procedure OpenItemClick(Sender: TObject);
    procedure ExitItemClick(Sender: TObject);
    procedure EncryptItemClick(Sender: TObject);
    procedure SaveItemClick(Sender: TObject);
    procedure CloseItemClick(Sender: TObject);
    procedure GetPassword;
    procedure EncryptData;
    procedure DecryptData;
    procedure DecryptItemClick(Sender: TObject);
    procedure ClearClick(Sender: TObject);
    procedure Autor1Click(Sender: TObject);
//    procedure InfoItemClick(Sender: TObject);
  private
    { Private declarations }
    plaintext, ciphertext: string;
      public
    { Public declarations }
    hProv: HCRYPTPROV;
    key: HCRYPTKEY;
        encrypt: boolean;
  end;

var
  MainForm: TMainForm;

implementation

uses Passwd;

{$R *.DFM}

type algInfo = record
     algID: ALG_ID;
     dwBits: DWORD;
     dwNameLen: DWORD;
     szName: array[0..100] of char;
     end;

procedure TMainForm.OpenItemClick(Sender: TObject);
begin
OpenDialog1.Title := 'Choose file';
OpenDialog1.Filter := 'All files (*.*)|*.*';
if OpenDialog1.Execute then
   begin
   plaintext := OpenDialog1.FileName;
   mFile.Lines.LoadFromFile(OpenDialog1.FileName);
   EncryptItem.Enabled := true;
   CloseItem.Enabled := true;
   end;
end;

procedure TMainForm.ExitItemClick(Sender: TObject);
begin
Close;
end;

function IntToHexFix(a:LongWord):string;
var b,r:string[8];
begin
  b:=IntToHex(a,8);
  SetLength(r,8);

  r[7]:=b[1];
  r[8]:=b[2];

  r[5]:=b[3];
  r[6]:=b[4];

  r[3]:=b[5];
  r[4]:=b[6];

  r[1]:=b[7];
  r[2]:=b[8];

  Result:=r;
end;

function MD5Calc(ciphertext:string): string;
var
    f1,f2:file;
    size:int64;
    buf:array of byte;
    buf64:TArr16xLongword;
    needadd:word;
    bu:byte;
    a,b,c,d:Longword;

   // ciphertext: string;
begin
    assignfile(f1,ciphertext);
    assignfile(f2,'c:\temp.$$$');
    reset(f1,1);
    size:=filesize(f1);
    reset(f1,size);
    setlength(buf,size);
    rewrite(f2,1);
    Application.ProcessMessages;
    blockread(f1,buf[0],1);
    closefile(f1);
    Application.ProcessMessages;
    blockwrite(f2,buf[0],size); //копирование файла - долго и надо много места
    finalize(buf);
    Application.ProcessMessages;

    if size>=56 then needadd:=(size-56)div 64*64+120-size
     else needadd:=56-size;
    bu:=$80;
    blockwrite(f2,bu,1); //добавляем биты "10000000"
    bu:=$00;
    for a:=2 to needadd do blockwrite(f2,bu,1); //добавляем биты "00000000"
    size:=size*8;
    blockwrite(f2,size,8); //добавляем размер: максимальный размер - 2^64 бита
    closefile(f2);
    Application.ProcessMessages;
    MD5Init;
    reset(f2,64);

    while not eof(f2) do begin
      blockread(f2,buf64,1);
      MD5Do(buf64); 
      end;
     closefile(f2);
    MD5Finalize(a,b,c,d);

    MessageDlg(IntToHexFix(a)+' '+IntToHexFix(b)+' '+
     IntToHexFix(c)+' '+IntToHexFix(d), mtInformation, [mbOK], 0);
     erase(f2);
      
end;

procedure TMainForm.GetPassword;
var err: string;
begin
if not CryptAcquireContext(@hProv, nil, nil, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) then
   begin
   case int64(GetLastError) of
   ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
   ERROR_NOT_ENOUGH_MEMORY: err := 'ERROR_NOT_ENOUGH_MEMORY';
   NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
   NTE_BAD_KEYSET: err := 'NTE_BAD_KEYSET';
   NTE_BAD_KEYSET_PARAM: err := 'NTE_BAD_KEYSET_PARAM';
   NTE_BAD_PROV_TYPE: err := 'NTE_BAD_PROV_TYPE';
   NTE_BAD_SIGNATURE: err := 'NTE_BAD_SIGNATURE';
   NTE_EXISTS: err := 'NTE_EXISTS';
   NTE_KEYSET_ENTRY_BAD: err := 'NTE_KEYSET_ENTRY_BAD';
   NTE_KEYSET_NOT_DEF: err := 'NTE_KEYSET_NOT_DEF';
   NTE_NO_MEMORY: err := 'NTE_NO_MEMORY';
   NTE_PROV_DLL_NOT_FOUND: err := 'NTE_PROV_DLL_NOT_FOUND';
   NTE_PROV_TYPE_ENTRY_BAD: err := 'NTE_PROV_TYPE_ENTRY_BAD';
   NTE_PROV_TYPE_NO_MATCH: err := 'NTE_PROV_TYPE_NO_MATCH';
   NTE_PROV_TYPE_NOT_DEF: err := 'NTE_PROV_TYPE_NOT_DEF';
   NTE_PROVIDER_DLL_FAIL: err := 'NTE_PROVIDER_DLL_FAIL';
   NTE_SIGNATURE_FILE_BAD: err := 'NTE_SIGNATURE_FILE_BAD';
   else err := 'Unknown error';
   end;
   MessageDlg('Error of CryptAcquireContext: '+err,
       mtError, [mbOK], 0);
   exit;
   end;
PasswordForm.Show;
end;

procedure TMainForm.EncryptItemClick(Sender: TObject);
begin
encrypt := true;
GetPassword;
end;

procedure TMainForm.EncryptData;
var i: integer;
    l: DWORD;
    err: string;
    data: PByte;
    inFile, outFile: file;

begin
SaveDialog1.Title := 'Where save the encrypt data?';
SaveDialog1.Filter := 'All files (*.*)|*.*|Encrypt files (*.enc)|*.enc';
SaveDialog1.FilterIndex := 2;
SaveDialog1.DefaultExt := 'enc';
if SaveDialog1.Execute then
   begin
   ciphertext := SaveDialog1.FileName;
   AssignFile(inFile, plaintext);
   AssignFile(outFile, ciphertext);
   reset(inFile, 1);
   rewrite(outFile, 1);
   GetMem(data, 512);
   while not eof(inFile) do
         begin
         BlockRead(inFile, data^, 512, l);
         if not CryptEncrypt(key, 0, eof(inFile), 0,
            data, @l, l) then
            begin
            case int64(GetLastError) of
            ERROR_INVALID_HANDLE: err := 'ERROR_INVALID_HANDLE';
            ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
            NTE_BAD_ALGID: err := 'NTE_BAD_ALGID';
            NTE_BAD_DATA: err := 'NTE_BAD_DATA';
            NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
            NTE_BAD_HASH: err := 'NTE_BAD_HASH';
            NTE_BAD_HASH_STATE: err := 'NTE_BAD_HASH_STATE';
            NTE_BAD_KEY: err := 'NTE_BAD_KEY';
            NTE_BAD_LEN: err := 'NTE_BAD_LEN';
            NTE_BAD_UID: err := 'NTE_BAD_UID';
            NTE_DOUBLE_ENCRYPT: err := 'NTE_DOUBLE_ENCRYPT';
            NTE_FAIL: err := 'NTE_FAIL';
            NTE_NO_MEMORY: err := 'NTE_NO_MEMORY';
            else err := 'Unknown error';
            end;
            MessageDlg('Error of CryptEncrypt: '+err,
                         mtError, [mbOK], 0);
            exit;
            end;
         BlockWrite(outFile, data^, l);
         end;
   FreeMem(data, 512);
   CloseFile(inFile);
   CloseFile(outFile);
   mFile.Lines.Clear;
   mFile.Lines.Add('MD5 Checksum:');
   MD5Calc(ciphertext);
   plaintext := '';
   ciphertext := '';
   EncryptItem.Enabled := false;

   end;
if not CryptReleaseContext(hProv, 0) then
   begin
   case int64(GetLastError) of
   ERROR_BUSY: err := 'ERROR_BUSY';
   ERROR_INVALID_HANDLE: err := 'ERROR_INVALID_HANDLE';
   ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
   NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
   NTE_BAD_UID: err := 'NTE_BAD_UID';
   else err := 'Unknown error';
   end;
   MessageDlg('Error of CryptReleaseContext: '+err,
       mtError, [mbOK], 0);
   end;
end;

procedure TMainForm.DecryptData;
var i: integer;
    l: DWORD;
    err: string;
    data: PByte;
    inFile, outFile: file;
begin
SaveDialog1.Title := 'Where save the decoded data?';
SaveDialog1.Filter := 'All files (*.*)|*.*|Decrypt files (*.dec)|*.dec|Text files (*.txt)|*.txt';
SaveDialog1.DefaultExt := 'dec';
if SaveDialog1.Execute then
   begin
   plaintext := SaveDialog1.FileName;
   AssignFile(inFile, ciphertext);
   AssignFile(outFile, plaintext);
   reset(inFile, 1);
   rewrite(outFile, 1);
   GetMem(data, 512);
   while not eof(inFile) do
         begin
         BlockRead(inFile, data^, 512, l);
         if not CryptDecrypt(key, 0, eof(inFile), 0,
            data, @l) then
            begin
            case int64(GetLastError) of
            ERROR_INVALID_HANDLE: err := 'ERROR_INVALID_HANDLE';
            ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
            NTE_BAD_ALGID: err := 'NTE_BAD_ALGID';
            NTE_BAD_DATA: err := 'NTE_BAD_DATA';
            NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
            NTE_BAD_HASH: err := 'NTE_BAD_HASH';
            NTE_BAD_HASH_STATE: err := 'NTE_BAD_HASH_STATE';
            NTE_BAD_KEY: err := 'NTE_BAD_KEY';
            NTE_BAD_LEN: err := 'NTE_BAD_LEN';
            NTE_BAD_UID: err := 'NTE_BAD_UID';
            NTE_DOUBLE_ENCRYPT: err := 'NTE_DOUBLE_ENCRYPT';
            NTE_FAIL: err := 'NTE_FAIL';
            NTE_NO_MEMORY: err := 'NTE_NO_MEMORY';
            else err := 'Unknown error';
            end;
            MessageDlg('Error of CryptDecrypt: '+err,
                         mtError, [mbOK], 0);
            exit;
            end;
         BlockWrite(outFile, data^, l);
         end;
   FreeMem(data, 512);
   CloseFile(inFile);
   CloseFile(outFile);
   mFile.Lines.LoadFromFile(plaintext);
   end;
end;

procedure TMainForm.SaveItemClick(Sender: TObject);
begin
SaveDialog1.Title := 'Choose filename';
SaveDialog1.Filter := 'All files (*.*)|*.*|Text files (*.txt)|*.txt';
SaveDialog1.DefaultExt := 'txt';
if SaveDialog1.Execute then
   begin
   plaintext := SaveDialog1.FileName;
   mFile.Lines.SaveToFile(plaintext);
   EncryptItem.Enabled := true;
   end;
end;

procedure TMainForm.CloseItemClick(Sender: TObject);
begin
mFile.Lines.Clear;
EncryptItem.Enabled := false;
plaintext := '';
ciphertext := '';
end;

procedure TMainForm.DecryptItemClick(Sender: TObject);
begin
OpenDialog1.Title := 'Choose file for decryption';
OpenDialog1.Filter := 'Encrypted files (*.enc)|*.ENC|All files (*.*)|*.*';
if OpenDialog1.Execute then
   begin
   ciphertext := OpenDialog1.FileName;
   encrypt := false;
   GetPassword;
   end;
end;

function ProvTypeToStr(provType: DWORD): string;
begin
case provType of
PROV_RSA_FULL: ProvTypeToStr := 'RSA full provider';
PROV_RSA_SIG: ProvTypeToStr := 'RSA signature provider';
PROV_DSS: ProvTypeToStr := 'DSS provider';
PROV_DSS_DH: ProvTypeToStr := 'DSS and Diffie-Hellman provider';
PROV_FORTEZZA: ProvTypeToStr := 'Fortezza provider';
PROV_MS_EXCHANGE: ProvTypeToStr := 'MS Exchange provider';
PROV_RSA_SCHANNEL: ProvTypeToStr := 'RSA secure channel provider';
PROV_SSL: ProvTypeToStr := 'SSL provider';
else ProvTypeToStr := 'Unknown provider';
end;
end;

function ImpTypeToStr(it: DWORD): string;
begin
case it of
CRYPT_IMPL_HARDWARE: ImpTypeToStr := 'аппаратный';
CRYPT_IMPL_SOFTWARE: ImpTypeToStr := 'программный';
CRYPT_IMPL_MIXED: ImpTypeToStr := 'смешанный';
CRYPT_IMPL_UNKNOWN: ImpTypeToStr := 'неизвестен';
else ImpTypeToStr := 'неверное значение';
end;
end;

{
procedure TMainForm.InfoItemClick(Sender: TObject);
var i: DWORD;
    dwProvType, cbName, DataLen: DWORD;
    provName: array[0..200] of char;
    vers: array[0..3] of byte;
    impType: DWORD;
    ai: algInfo;
    err: string;
begin
i:= 0;
mFile.Clear;
while (CryptEnumProvidersW(i, nil, 0,
      @dwProvType, nil, @cbName)) do
      begin
      if CryptEnumProvidersW(i, nil, 0,
         @dwProvType, @provName, @cbName) then
         begin
         mFile.Lines.Add('Криптопровайдер: '+provName);
         mFile.Lines.Add('Тип: '+IntToStr(dwProvType)+' - '+
                               ProvTypeToStr(dwProvType));
         if not CryptAcquireContext(@hProv,nil,provName,dwProvType,CRYPT_VERIFYCONTEXT)
         then
             begin
             case int64(GetLastError) of
             ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
             ERROR_NOT_ENOUGH_MEMORY: err := 'ERROR_NOT_ENOUGH_MEMORY';
             NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
             NTE_BAD_KEYSET: err := 'NTE_BAD_KEYSET';
             NTE_BAD_KEYSET_PARAM: err := 'NTE_BAD_KEYSET_PARAM';
             NTE_BAD_PROV_TYPE: err := 'NTE_BAD_PROV_TYPE';
             NTE_BAD_SIGNATURE: err := 'NTE_BAD_SIGNATURE';
             NTE_EXISTS: err := 'NTE_EXISTS';
             NTE_KEYSET_ENTRY_BAD: err := 'NTE_KEYSET_ENTRY_BAD';
             NTE_KEYSET_NOT_DEF: err := 'NTE_KEYSET_NOT_DEF';
             NTE_NO_MEMORY: err := 'NTE_NO_MEMORY';
             NTE_PROV_DLL_NOT_FOUND: err := 'NTE_PROV_DLL_NOT_FOUND';
             NTE_PROV_TYPE_ENTRY_BAD: err := 'NTE_PROV_TYPE_ENTRY_BAD';
             NTE_PROV_TYPE_NO_MATCH: err := 'NTE_PROV_TYPE_NO_MATCH';
             NTE_PROV_TYPE_NOT_DEF: err := 'NTE_PROV_TYPE_NOT_DEF';
             NTE_PROVIDER_DLL_FAIL: err := 'NTE_PROVIDER_DLL_FAIL';
             NTE_SIGNATURE_FILE_BAD: err := 'NTE_SIGNATURE_FILE_BAD';
             else err := 'Unknown error';
             end;
             MessageDlg('Error of CryptAcquireContext: '+err,
                               mtError, [mbOK], 0);
             exit;
             end;
         DataLen := 4;
         if not CryptGetProvParam(hProv, PP_VERSION, (@vers), @DataLen, 0)
         then
             begin
             case int64(GetLastError) of
             ERROR_INVALID_HANDLE: err := 'ERROR_INVALID_HANDLE';
             ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
             ERROR_MORE_DATA: err := 'ERROR_MORE_DATA';
             ERROR_NO_MORE_ITEMS: err := 'ERROR_NO_MORE_ITEMS';
             NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
             NTE_BAD_TYPE: err := 'NTE_BAD_TYPE';
             NTE_BAD_UID: err := 'NTE_BAD_UID';
             else err := 'Unknown error';
             end;
             MessageDlg('Error of CryptGetProvParam: '+err,mtError,[mbOK],0);
             exit
             end;
         mFile.Lines.Add('Версия: '+chr(vers[1]+$30)+'.'+chr(vers[0]+$30));
         if not CryptGetProvParam(hProv, PP_IMPTYPE, (@impType), @DataLen, 0)
         then
             begin
             case int64(GetLastError) of
             ERROR_INVALID_HANDLE: err := 'ERROR_INVALID_HANDLE';
             ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
             ERROR_MORE_DATA: err := 'ERROR_MORE_DATA';
             ERROR_NO_MORE_ITEMS: err := 'ERROR_NO_MORE_ITEMS';
             NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
             NTE_BAD_TYPE: err := 'NTE_BAD_TYPE';
             NTE_BAD_UID: err := 'NTE_BAD_UID';
             else err := 'Unknown error';
             end;
             MessageDlg('Error of CryptGetProvParam: '+err,mtError,[mbOK],0);
             exit
             end;
         mFile.Lines.Add('Тип реализации: '+ImpTypeToStr(impType));
         mFile.Lines.Add('Поддерживает алгоритмы:');
         DataLen := sizeof(ai);
         if not CryptGetProvParam(hProv, PP_ENUMALGS, (@ai), @DataLen, CRYPT_FIRST)
         then
             begin
             case int64(GetLastError) of
             ERROR_INVALID_HANDLE: err := 'ERROR_INVALID_HANDLE';
             ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
             ERROR_MORE_DATA: err := 'ERROR_MORE_DATA';
             ERROR_NO_MORE_ITEMS: err := 'ERROR_NO_MORE_ITEMS';
             NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
             NTE_BAD_TYPE: err := 'NTE_BAD_TYPE';
             NTE_BAD_UID: err := 'NTE_BAD_UID';
             else err := 'Unknown error';
             end;
             MessageDlg('Error of CryptGetProvParam: '+err,mtError,[mbOK],0);
             exit
             end;
         with ai do
         mFile.Lines.Add(szName+#9+'длина ключа - '+IntToStr(dwBits)+' бит'+#9+
                                   'ID: '+IntToStr(AlgID));
         DataLen := sizeof(ai);
         while CryptGetProvParam(hProv, PP_ENUMALGS, (@ai), @DataLen, 0) do
               begin
               with ai do mFile.Lines.Add(szName+#9+'длина ключа - '
                    +IntToStr(dwBits)+' бит'+#9+'ID: '+IntToStr(AlgID));
               DataLen := sizeof(ai);
               end;
         mFile.Lines.Add('');
         CryptReleaseContext(hProv, 0);
         end;
      inc(i);
      end;
end;       }

procedure TMainForm.ClearClick(Sender: TObject);
begin
  mFile.Clear;
end;

procedure TMainForm.Autor1Click(Sender: TObject);
begin
   //MessageDlg('Author: CBuH',
     //                    mtInformation, [mbOK], 0);
   mFile.Lines.Add('Author: cbin, 2005-2006');
   mFile.Lines.Add('Email: cbin@users.sourceforge.net');
   mFile.Lines.Add('Homepage: http://cryptx.sf.net');
end;

end.
