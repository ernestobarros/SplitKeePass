#r @"packages/security/KeePassLib/lib/KeePassLib.dll"
open KeePassLib
open KeePassLib.Keys
open KeePassLib.Serialization
open KeePassLib.Security
open System
open System.IO
open System.Text.RegularExpressions

type BridgeEntry =
    {
        title: string
        url: string
        pass: string
    }

type ConfigSettings =
    {
        bridgePath: string;
        bridgePass: string;
        bridgeEntries: BridgeEntry list
        sourcePath: string;
        sourcePass: string
        targetPath: string;
        targetPass: string
    }

let config =
    {
        bridgePath = "DummyBridgeDB.kdbx"
        bridgePass = null
        bridgeEntries = [
                        {title = "ProdDB"; pass = "1"; url = "DummySourceDB.kdbx"}
                        {title = "TestDB"; pass = "2"; url = "DummyTargetDB.kdbx"}
                        ]
        sourcePath = "DummySourceDB.kdbx"
        sourcePass = "1"
        targetPath = "DummyTargetDB.kdbx"
        targetPass = "2"
    }

let makeCompositeKey (dbPass: string) =
    let key = CompositeKey()
    if isNull dbPass then
        // Use the current Windows user account
        key.AddUserKey(KcpUserAccount())
    else
        key.AddUserKey(KcpPassword(dbPass))
    key

let getDB (dbPath: string) (dbPass: string) =
    Environment.CurrentDirectory <- __SOURCE_DIRECTORY__
    let key = makeCompositeKey dbPass
    let db = PwDatabase()
    db.Open(IOConnectionInfo(Path = dbPath), key, null)
    db

let createKdbxDatabase dbPath dbPass =
    Environment.CurrentDirectory <- __SOURCE_DIRECTORY__
    let db = PwDatabase()
    db.Name <- Path.GetFileNameWithoutExtension(dbPass)
    db.MasterKey <- makeCompositeKey dbPass
    let kdbx = KdbxFile(db)
    let groupDataSoucrce = PwGroup(true, true)
    use streamToFile = File.OpenWrite(dbPath)
    kdbx.Save(streamToFile, groupDataSoucrce, KdbxFormat.Default, null)

let createBridgeDB () =
    let dbPath = config.bridgePath
    let dbPass = config.bridgePass
    if File.Exists dbPath then File.Delete dbPath
    createKdbxDatabase dbPath dbPass
    let db = getDB dbPath dbPass
    let addEntry (bridgeEntry: BridgeEntry) =
        PwEntry(true, true)
        |> fun entry ->
            entry.IconId <- PwIcon.Settings
            entry.Strings.Set(PwDefs.TitleField, ProtectedString(false, bridgeEntry.title))
            entry.Strings.Set(PwDefs.UrlField, ProtectedString(false, bridgeEntry.url))
            entry.Strings.Set(PwDefs.PasswordField, ProtectedString(true, bridgeEntry.pass))
            db.RootGroup.AddEntry(entry, true)
    // Populate the bridge DB
    config.bridgeEntries |> List.iter addEntry
    db.Save(null)
    db.Close()

let createSourceDB () =
    let dbPath = config.sourcePath
    let dbPass = config.sourcePass
    if File.Exists dbPath then File.Delete dbPath
    createKdbxDatabase dbPath dbPass
    let db = getDB dbPath dbPass
    let addGroup (groupName: string) =
        PwGroup(true, true)
        |> fun group ->
            group.IconId <- PwIcon.Configuration
            group.Name <- groupName
            db.RootGroup.AddGroup(group, true, true)
    // Populate the source DB with groups
    ["Database"; "FTP"] |> List.iter addGroup
    let addEntry (title: string, user: string, pass: string) =
        PwEntry(true, true)
        |> fun entry ->
            entry.IconId <- PwIcon.Settings
            entry.Strings.Set(PwDefs.TitleField, ProtectedString(false, title))
            entry.Strings.Set(PwDefs.UserNameField, ProtectedString(false, user))
            entry.Strings.Set(PwDefs.PasswordField, ProtectedString(true, pass))
            db.RootGroup.GetGroups(false)
            |> Seq.filter (fun g -> g.Name = "Database")
            |> Seq.exactlyOne
            |> fun g -> g.AddEntry(entry, true)
    // Populate the source DB with entries
    [
        ("XXX-SQLTEST.app1", "app1user", "1")
        ("XXX-SQLTEST.app2", "app2user", "2")
    ] |> List.iter addEntry
    db.Save(null)
    db.Close()

let createTargetDB () =
    let dbPath = config.targetPath
    let dbPass = config.targetPass
    if File.Exists dbPath then File.Delete dbPath
    createKdbxDatabase dbPath dbPass

(*
    create the dummy databases
*)
createBridgeDB ()
createSourceDB ()
createTargetDB ()

// DO IT!!
let getEntries (db: PwDatabase) filterEntries =
    db.RootGroup.GetEntries true
    |> Seq.filter filterEntries

let getProdDB () =
    let dbBridge = getDB config.bridgePath config.bridgePass
    let getPassDB (entries: seq<PwEntry>) =
        entries
        |> Seq.map (fun entry -> (entry.Strings.ReadSafe("URL"), entry.Strings.ReadSafe("Password")))
        |> Seq.exactlyOne
    let (dbPath, dbPass) =
        let filter = fun (entry:PwEntry) -> entry.Strings.ReadSafe("Title") = "ProdDB"
        getPassDB <| getEntries dbBridge filter
    dbBridge.Close()
    let dbProd = getDB dbPath dbPass
    dbProd

let getTestDB () =
    let dbBridge = getDB config.bridgePath config.bridgePass
    let getPassDB (entries: seq<PwEntry>) =
        entries
        |> Seq.map (fun entry -> (entry.Strings.ReadSafe("URL"), entry.Strings.ReadSafe("Password")))
        |> Seq.exactlyOne
    let (dbPath, dbPass) =
        let filter = fun (entry:PwEntry) -> entry.Strings.ReadSafe("Title") = "TestDB"
        getPassDB <| getEntries dbBridge filter
    dbBridge.Close()
    let dbTest = getDB dbPath dbPass
    dbTest

let doSplitDB () =
    let getSourceEntries () =
        let sourceDB = getProdDB ()
        let filterDB = fun (pe:PwEntry) ->
            [
                fun _ ->
                    pe.ParentGroup.Name = "Database"
                    && Regex.IsMatch(pe.Strings.ReadSafe(PwDefs.TitleField), "XXX-SQLTEST", RegexOptions.IgnoreCase)
                fun _ ->
                    pe.ParentGroup.Name = "FTP"
                    && Regex.IsMatch(pe.Strings.ReadSafe(PwDefs.TitleField), "TEST", RegexOptions.IgnoreCase)
            ]
            |> List.exists (fun f -> f())
        let entries = getEntries sourceDB filterDB
        sourceDB.Close()
        entries
    let addEntries (db: PwDatabase) (entries: PwEntry seq) =
        let addParentGroup (sourceGroup: PwGroup) =
            db.RootGroup.AddGroup(PwGroup(true, true, sourceGroup.Name, sourceGroup.IconId), true)
        let addEntry = fun (pe: PwEntry) ->
            if isNull <| db.RootGroup.FindCreateGroup(pe.ParentGroup.Name, false) then
                addParentGroup pe.ParentGroup
            let targetGroup = db.RootGroup.FindCreateGroup(pe.ParentGroup.Name, false)
            if isNull <| targetGroup.FindEntry(pe.Uuid, false) then
                targetGroup.AddEntry(pe, true)
        entries
        |> Seq.iter addEntry
        db.Save(null)
        db.Close()
    let targetDB = getTestDB ()
    let targetEntries = getSourceEntries ()
    // DO IT!!
    addEntries targetDB targetEntries

doSplitDB ()

