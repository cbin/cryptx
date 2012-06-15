program EncByPass;

{%DelphiDotNetAssemblyCompiler '$(SystemRoot)\microsoft.net\framework\v1.1.4322\System.Drawing.dll'}
{%DelphiDotNetAssemblyCompiler 'd:\program files\common files\borland shared\bds\shared assemblies\2.0\Borland.Vcl.dll'}
{%DelphiDotNetAssemblyCompiler 'd:\program files\common files\borland shared\bds\shared assemblies\2.0\Borland.Delphi.dll'}
{%DelphiDotNetAssemblyCompiler 'd:\program files\common files\borland shared\bds\shared assemblies\2.0\Borland.VclRtl.dll'}
{%DelphiDotNetAssemblyCompiler '$(SystemRoot)\Microsoft.NET\Framework\v1.1.4322\System.dll'}

uses
  Forms,
  Main in 'Main.pas' {MainForm},
  Wcrypt2 in '..\..\Lib\Crypto\Pas\Wcrypt2.pas',
  Passwd in 'Passwd.pas' {PasswordForm};

{$R *.RES}

begin
  Application.Initialize;
  Application.CreateForm(TMainForm, MainForm);
  Application.CreateForm(TPasswordForm, PasswordForm);
  Application.Run;
end.
