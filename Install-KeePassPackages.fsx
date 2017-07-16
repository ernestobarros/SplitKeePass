// Run the steps separately with F# interactive
// Select the code for the step and choose ALT+ENTER

//------------------------------------------
// Step 0. Get the package bootstrap. This is standard F# boiler plate for scripts that also get packages.
open System
open System.IO
let packagesDir = __SOURCE_DIRECTORY__ + "/script-packages"
Directory.CreateDirectory(packagesDir)
Environment.CurrentDirectory <- packagesDir
if not (File.Exists "paket.exe") then
    let url = "https://github.com/fsprojects/Paket/releases/download/1.2.0/paket.bootstrapper.exe" in use wc = new System.Net.WebClient() in let tmp = Path.GetTempFileName() in wc.DownloadFile(url, tmp); File.Move(tmp,"paket.bootstrapper.exe"); System.Diagnostics.Process.Start("paket.bootstrapper.exe") |> ignore;;

//------------------------------------------
// Step 1. Resolve and install the Canopy package and the Chrome web driver
// You can add any additional packages you like to this step.
#r "script-packages/paket.exe"
Paket.Dependencies.Install """
group Security
    source https://nuget.org/api/v2
    nuget KeePassLib
    github saintedlama/keepasschrome:63d150f sample/sample.kdbx
    github twsouthwick/KeePassLib:f868002 KeePassLibTest/Assets/password-aes_rijndael_256.kdbx
""";;

//------------------------------------------
// Step 2. Reference the .. framework libraries
#r @"script-packages/packages/security/KeePassLib/lib/KeePassLib.dll"
open KeePassLib
open KeePassLib.Keys
open KeePassLib.Serialization

//------------------------------------------
// Step 3. Sample files
let dbPath = "paket-files\security\saintedlama\keepasschrome\sample\sample.kdbx"
// let dbPath = "paket-files/security/twsouthwick/KeePassLib/KeePassLibTest/Assets/password-aes_rijndael_256.kdbx"
let key = CompositeKey()
key.AddUserKey(KcpPassword("password"))
// key.AddUserKey(new KcpPassword("12345"))
let db = PwDatabase()
db.Open(IOConnectionInfo(Path = dbPath), key, null)

let printPwEntry (entry: PwEntry) =
    printfn @"
    Group    %s
    Title    %s
    Username %s
    Password %s
    URL      %s
    Notes    %s
    "
    <| entry.ParentGroup.Name
    <| entry.Strings.ReadSafe("Title")
    <| entry.Strings.ReadSafe("UserName")
    <| entry.Strings.ReadSafe("Password")
    <| entry.Strings.ReadSafe("URL")
    <| entry.Strings.ReadSafe("Notes")
db.RootGroup.GetEntries true
|> Seq.iter printPwEntry
