unit Passwd;

interface

uses
  Windows, Messages, SysUtils, Classes, Graphics, Controls, Forms, Dialogs,
  StdCtrls, Buttons, wcrypt2;

type
  TPasswordForm = class(TForm)
    Label1: TLabel;
    tFirstPass: TEdit;
    Label2: TLabel;
    tPasswAgain: TEdit;
    btnClose: TButton;
    btnOK: TButton;
//    procedure CancelBitBtnClick(Sender: TObject);
  //  procedure OkBitBtnClick(Sender: TObject);
    procedure tPasswAgainChange(Sender: TObject);
    procedure btnCloseClick(Sender: TObject);
    procedure btnOKClick(Sender: TObject);
  private
    { Private declarations }
  public
    { Public declarations }
  end;

var
  PasswordForm: TPasswordForm;

implementation

uses Main;

{$R *.DFM}

procedure TPasswordForm.tPasswAgainChange(Sender: TObject);
begin
if (Length(tFirstPass.Text)>0) and (tFirstPass.Text = tPasswAgain.Text)
then btnOK.Enabled := true
else btnOK.Enabled := false;
end;

procedure TPasswordForm.btnCloseClick(Sender: TObject);
begin
tFirstPass.Text := '';
Close;
end;

procedure TPasswordForm.btnOKClick(Sender: TObject);
//begin
var hash: HCRYPTHASH;
    err: string;
begin
if not CryptCreateHash(MainForm.hProv, CALG_SHA, 0, 0, @hash) then
   begin
   case int64(GetLastError) of
   ERROR_INVALID_HANDLE: err := 'ERROR_INVALID_HANDLE';
   ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
   ERROR_NOT_ENOUGH_MEMORY: err := 'ERROR_NOT_ENOUGH_MEMORY';
   NTE_BAD_ALGID: err := 'NTE_BAD_ALGID';
   NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
   NTE_BAD_KEY: err := 'NTE_BAD_KEY';
   NTE_NO_MEMORY: err := 'NTE_NO_MEMORY';
   else err := 'Unknown error';
   end;
   MessageDlg('Error of CryptCreateHash: '+err,
       mtError, [mbOK], 0);
   exit;
   end;
if not CryptHashData(hash, @tFirstPass.text[1], length(tFirstPass.text), 0) then
   begin
   case int64(GetLastError) of
   ERROR_INVALID_HANDLE: err := 'ERROR_INVALID_HANDLE';
   ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
   NTE_BAD_ALGID: err := 'NTE_BAD_ALGID';
   NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
   NTE_BAD_HASH: err := 'NTE_BAD_HASH';
   NTE_BAD_HASH_STATE: err := 'NTE_BAD_HASH_STATE';
   NTE_BAD_KEY: err := 'NTE_BAD_KEY';
   NTE_BAD_LEN: err := 'NTE_BAD_LEN';
   NTE_BAD_UID: err := 'NTE_BAD_UID';
   NTE_FAIL: err := 'NTE_FAIL';
   NTE_NO_MEMORY: err := 'NTE_NO_MEMORY';
   else err := 'Unknown error';
   end;
   MessageDlg('Error of CryptHashData: '+err,
       mtError, [mbOK], 0);
   exit;
   end;
if not CryptDeriveKey(MainForm.hProv, CALG_RC4, hash, 0, @MainForm.key) then
   begin
   case int64(GetLastError) of
   ERROR_INVALID_HANDLE: err := 'ERROR_INVALID_HANDLE';
   ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
   NTE_BAD_ALGID: err := 'NTE_BAD_ALGID';
   NTE_BAD_FLAGS: err := 'NTE_BAD_FLAGS';
   NTE_BAD_HASH: err := 'NTE_BAD_HASH';
   NTE_BAD_HASH_STATE: err := 'NTE_BAD_HASH_STATE';
   NTE_BAD_UID: err := 'NTE_BAD_UID';
   NTE_FAIL: err := 'NTE_FAIL';
   else err := 'Unknown error';
   end;
   MessageDlg('Error of CryptHashData: '+err,
       mtError, [mbOK], 0);
   exit;
   end;
if not CryptDestroyHash(hash) then
   begin
   case int64(GetLastError) of
   ERROR_BUSY: err := 'ERROR_BUSY';
   ERROR_INVALID_HANDLE: err := 'ERROR_INVALID_HANDLE';
   ERROR_INVALID_PARAMETER: err := 'ERROR_INVALID_PARAMETER';
   NTE_BAD_ALGID: err := 'NTE_BAD_ALGID';
   NTE_BAD_HASH: err := 'NTE_BAD_HASH';
   NTE_BAD_UID: err := 'NTE_BAD_UID';
   else err := 'Unknown error';
   end;
   MessageDlg('Error of CryptDestroyHash: '+err,
       mtError, [mbOK], 0);
   exit;
   end;
if MainForm.encrypt then MainForm.EncryptData
else MainForm.DecryptData;
tFirstPass.Text := '';
tPasswAgain.Text := '';
Close;
end;
//end;

end.
