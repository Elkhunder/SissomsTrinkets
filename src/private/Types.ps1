enum DellCommandStatus {
    Present
    Installed
    Failed
}

class DellCommandResult {
    [string]$ComputerName
    [bool]$Exists
    [string]$Path
    [DellCommandStatus]$Status

    DellCommandResult([string]$computerName, [bool]$exists, [string]$path, [DellCommandStatus]$status){
        $this.ComputerName = $computerName
        $this.Exists = $exists
        $this.Path = $path
        $this.Status = $status
    }
}