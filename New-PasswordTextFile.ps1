Function New-PasswordTextFile{
    param([string] $filename)
    read-host -assecurestring | convertfrom-securestring | out-file $filename
}

New-PasswordTextFile -filename "c:\dsc\dsc.txt"
New-PasswordTextFile -filename "c:\dsc\certpass.txt"