Description: Glessner's additions to DFIRBatch.reb
Author: Glessner
Version: 1
Id: 547b84a5-e2ea-475a-abe2-fdc1588dbecf
Keys:
    # Glessner's additions, from recmd_additions.reb in its registry folder: values DFIRBatch.reb doesn't read. A run of
    # RECmd reads DFIRBatch.reb's entries, in their order, and then these. Each entry's Description is part of the event
    # IDs of the rows it writes, so it stays as it is, and any change to this file comes with a new Version.

    -
        Description: Windows Version
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion
        ValueName: CurrentVersion
        Recursive: false
        Comment: "Windows version number, such as 6.1 for Windows 7 and Windows Server 2008 R2"

    -
        Description: Internet Explorer Version
        HiveType: SOFTWARE
        Category: Web Browsers
        KeyPath: Microsoft\Internet Explorer
        ValueName: svcVersion
        Recursive: false
        Comment: "Internet Explorer's version, as Internet Explorer 10 and later record it"

    -
        Description: Network Cards
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows NT\CurrentVersion\NetworkCards\*
        Recursive: false
        Comment: "Each network adapter's name (Description) and its interface GUID (ServiceName), which names the adapter's key among the Tcpip interfaces in SYSTEM"

    -
        Description: Default Mail Client
        HiveType: SOFTWARE
        Category: Installed Software
        KeyPath: Clients\Mail
        ValueName: (default)
        Recursive: false
        Comment: "The default e-mail program, in the (default) value"

    -
        Description: Mailto Handler
        HiveType: SOFTWARE
        Category: Installed Software
        KeyPath: Classes\mailto\shell\open\command
        Recursive: false
        Comment: "The command line that opens mailto: links"

    -
        Description: Windows Search Index
        HiveType: SOFTWARE
        Category: System Info
        KeyPath: Microsoft\Windows Search\Databases\Windows
        ValueName: FileName
        Recursive: false
        Comment: "The path of the Windows Search index database"

    -
        Description: CD Burning
        HiveType: NTUSER
        Category: User Activity
        KeyPath: Software\Microsoft\Windows\CurrentVersion\Explorer\CD Burning
        ValueName: DefaultToMastered
        Recursive: false
        Comment: "The disc format Windows Explorer burns by default: 1 for Mastered, 0 for the Live File System"

    -
        Description: Google Drive
        HiveType: NTUSER
        Category: Cloud Storage
        KeyPath: Software\Google\Drive
        Recursive: false
        Comment: "The user's Google Drive settings, such as the path of its synced folder"

    -
        Description: Google Drive File Types
        HiveType: UsrClass
        Category: Cloud Storage
        KeyPath: GoogleDrive.*\shell\open\command
        Recursive: false
        Comment: "Each file type Google Drive registered for the user, such as GoogleDrive.gdoc, with the command line that opens it"

    -
        Description: Installed Printers
        HiveType: SOFTWARE
        Category: Devices
        KeyPath: Microsoft\Windows NT\CurrentVersion\Print\Printers\*
        ValueName: Name
        Recursive: false
        Comment: "Each printer installed on the system, by name"
