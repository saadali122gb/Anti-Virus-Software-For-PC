Set oWS = WScript.CreateObject("WScript.Shell")
sLinkFile = oWS.SpecialFolders("Desktop") & "\Network Jammer.lnk"
Set oLink = oWS.CreateShortcut(sLinkFile)
oLink.TargetPath = "powershell.exe"
oLink.Arguments = "-NoProfile -WindowStyle Hidden -ExecutionPolicy Bypass -Command ""Start-Process powershell -ArgumentList '-NoProfile -ExecutionPolicy Bypass -Command \"\"Set-Location ''d:\Soft House\Network Jammer''; npm start\"\"' -Verb RunAs"""
oLink.Description = "Open Network Jammer as Administrator"
oLink.WorkingDirectory = "d:\Soft House\Network Jammer"
oLink.Save
