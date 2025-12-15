Describe "IIS Hardener basics" {
    It "New-RunStamp returns a timestamp-like string" {
        . "$PSScriptRoot\..\src\IIS-Hardener-GUI.ps1"
        $s = New-RunStamp
        $s | Should -Match '^\d{8}_\d{6}_\d{3}$'
    }
}
