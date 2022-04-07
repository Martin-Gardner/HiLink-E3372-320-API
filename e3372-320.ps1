#requires -version 4

#########################################################################################
# Internal Functions
#########################################################################################
function New-API-Request-InternalFunction
{
    
    <#
    .SYNOPSIS
        Performs an API called against a E3372-320 4G Modem running in HiLink Mode
    .DESCRIPTION
        Supports POST and GET requests to API running on the 
        E3372-320 4G Modem running in HiLink Mode
    .EXAMPLE
        New-API-Request-InternalFunction -IP_Or_Hostname "192.168.8.1" -API_Path "/api/deviceinformation"
    .INPUTS
        IP_Or_Hostname - IP Address or Hostname of the E3372-320 4G Modem running in HiLink Mode
        API_Path - The API path to call
        PostData - Body of the POST request
    .OUTPUTS
        HTTP_Response - The response from the API call
    .NOTES
        Version:        1.0
        By:             Martin Gardner
    #>

    Param (
        [Parameter(Mandatory=$true, HelpMessage='IP Address or Hostname of the Modem')]
        [ValidateNotNullOrEmpty()]
        [string]$IP_Or_Hostname,

        [Parameter(Mandatory=$true, HelpMessage='API Command to be executed')]
        [ValidateNotNullOrEmpty()]
        [string]$API_Path,

        [Parameter(Mandatory=$false, HelpMessage='API XML for post request')]
        [string]$PostData = ''
    )

    try {
        # Try to obtain SessionID Cookie and Security Token from the Modem
        $TokenResponse = (Invoke-RestMethod -Uri "http://$IP_Or_Hostname/api/webserver/SesTokInfo" -Method Get )
    }
    catch {
        # Invoke-RestMethod throws an exception if the Modem is not reachable
        throw "Unable to obtain SessionID and Security Token from the Modem"
    }

    <#
        Obtain SessionID and Security Token from the Modem
        these are used for subsequent API requests
    #>
    $SessionKey = $TokenResponse.response.TokInfo # Set Session Key from Token Response
    $SessionID  = $TokenResponse.response.SesInfo # Set Sssion ID from Token Response

    <#
        Validate that the SessionID and Security Token were obtained and are not empty
    #>
    if([String]::IsNullOrEmpty($SessionID) -or [String]::IsNullOrEmpty($SessionKey))
    {
        # No data was returned from the Modem that could be parsed
        throw "Failed to get session ID and key"
    }


    <#
        Add the Session Key to the HTTP Header
        Add the Session ID to the Cookie

        Note: I was unable to add the cookie to the headers array
              as this caused the API request to fail  
    #>
    $headers = @{"__RequestVerificationToken" = $SessionKey} # Add Session Key to HTTP Header
    
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $cookie = New-Object System.Net.Cookie 
    $cookie.Name = "SessionID"
    $cookie.Value = $SessionID
    $cookie.Domain = $IP_Or_Hostname
    $session.Cookies.Add($cookie) # Add Session ID to Cookie, then add Cookie to Session Variable
    
    # Create an empty xml document to store the API response in
    [xml]$response = ""

    <#
        Check to see if the Param PostData is empty, if it is assume that this is a GET request
        otherwise assume that this is a POST request
    #>
    if($PostData -eq "")
    {
        # Try to perform a GET request
        try {
            [xml]$response = (Invoke-RestMethod -Uri "http://$IP_Or_Hostname$API_Path" -Method Get -ContentType "text/xml" -Headers $headers -WebSession $session)
        }
        catch {
            throw "Unable to perform GET request to modem"
        }
    }
    else 
    {
        try {
            # Try to perform a POST request
            [xml]$response = (Invoke-RestMethod -Uri "http://$IP_Or_Hostname$API_Path" -Method Post -ContentType "text/xml" -Headers $headers -Body $PostData -WebSession $session)
        }
        catch {
            throw "Unable to perform POST request to modem"
        }
    }

    <#
        Check to see if the API response contains an error core from the modem
    #>
    $api_errorcheck = $response.error.code # Obtain Possible Error Code from API Response
    $api_error = "" # Create a string to hold error if found
    <# 
        Check to see if $api_errorcheck is NullOrEmpty, if it is not process for error code
        this will check against known error codes stored in this function and return 
        a nicer error message
    #>
    if(!([string]::IsNullOrEmpty($api_errorcheck)))
    {
        # Parse $api_errorcheck
        switch ($api_errorcheck) {
            "-1"     { $api_error = "system not available`r`n" + $response.innerxml}
            "100002" { $api_error = "not supported by firmware or incorrect API path`r`n" + $response.innerxml}
            "100003" { $api_error = "unauthorized`r`n" + $response.innerxml}
            "100004" { $api_error = "system busy`r`n" + $response.innerxml}
            "100005" { $api_error = "unknown error`r`n" + $response.innerxml}
            "100006" { $api_error = "invalid parameter`r`n" + $response.innerxml}
            "100009" { $api_error = "write error`r`n" + $response.innerxml}
            "103002" { $api_error = "unknown error`r`n" + $response.innerxml}
            "103015" { $api_error = "unknown error`r`n" + $response.innerxml}
            "108001" { $api_error = "invalid username`r`n" + $response.innerxml}
            "108002" { $api_error = "invalid password`r`n" + $response.innerxml}
            "108003" { $api_error = "user already logged in`r`n" + $response.innerxml}
            "108006" { $api_error = "invalid username or password`r`n" + $response.innerxml}
            "108007" { $api_error = "invalid username} password} or session timeout`r`n" + $response.innerxml}
            "110024" { $api_error = "battery charge less than 50%`r`n" + $response.innerxml}
            "111019" { $api_error = "no network response`r`n" + $response.innerxml}
            "111020" { $api_error = "network timeout`r`n" + $response.innerxml}
            "111022" { $api_error = "network not supported`r`n" + $response.innerxml}
            "113018" { $api_error = "system busy`r`n" + $response.innerxml}
            "114001" { $api_error = "file already exists`r`n" + $response.innerxml}
            "114002" { $api_error = "file already exists`r`n" + $response.innerxml}
            "114003" { $api_error = "SD card currently in use`r`n" + $response.innerxml}
            "114004" { $api_error = "path does not exist`r`n" + $response.innerxml}
            "114005" { $api_error = "path too long`r`n" + $response.innerxml}
            "114006" { $api_error = "no permission for specified file or directory`r`n" + $response.innerxml}
            "115001" { $api_error = "unknown error`r`n" + $response.innerxml}
            "117001" { $api_error = "incorrect WiFi password`r`n" + $response.innerxml}
            "117004" { $api_error = "incorrect WISPr password`r`n" + $response.innerxml}
            "120001" { $api_error = "voice busy`r`n" + $response.innerxml}
            "125001" { $api_error = "invalid token`r`n" + $response.innerxml}
            "113114" { $api_error = "Message Index out of range or message index not found`r`n" + $response.innerxml}
            default  { "Unkown error retuned from API`r`n" + $response.innerxml}
        }
        if(!([String]::IsNullOrEmpty($api_error)))
        {
            throw "Error accessing http://$IP_Or_Hostname$API_Path - $api_error"
        }
        else {
            # Not sure how we would get here - but handled just in case
            # in which case throw back whole response to caller
            throw "Unknown error returned from API - $response"
        }
    }
    else {
        # No error reported in xml response from modem - return response
        return $response
    }
}
function Get-Hash
{
    Param
    (
        [parameter(Mandatory=$true, ValueFromPipeline=$true, ParameterSetName="set1")]
        [String]
        $text,
        
        [parameter(Position=0, Mandatory=$true, 
        ValueFromPipeline=$false, ParameterSetName="set2")]
        [String]
        $file = "",
        
        [parameter(Mandatory=$false, ValueFromPipeline=$false)]
        [ValidateSet("MD5", "SHA", "SHA1", "SHA-256", "SHA-384", "SHA-512")]
        [String]
        $algorithm = "SHA1"
    )
    Begin
    {
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithm]::Create($algorithm)
    }
    Process
    {
        $md5StringBuilder = New-Object System.Text.StringBuilder 50
        $ue = New-Object System.Text.UTF8Encoding

        if ($file){
            try {
                if (!(Test-Path -literalpath $file)){
                    throw "Test-Path returned false."
                }
            }
            catch {
                throw "Get-Hash - File not found or without permisions: [$file]. $_"
            }
            try {
                [System.IO.FileStream]$fileStream = [System.IO.File]::Open($file, [System.IO.FileMode]::Open);
                $hashAlgorithm.ComputeHash($fileStream) | 
                    ForEach-Object { [void] $md5StringBuilder.Append($_.ToString("x2")) }
            }
            catch {
                throw "Get-Hash - Error reading or hashing the file: [$file]"
            }
            finally {
                $fileStream.Close()
                $fileStream.Dispose()
            }
        }
        else {
            $hashAlgorithm.ComputeHash($ue.GetBytes($text)) | 
                ForEach-Object { [void] $md5StringBuilder.Append($_.ToString("x2")) }
        }

        return $md5StringBuilder.ToString()
    }
}

#########################################################################################
# SMS Functions
#########################################################################################
function New-E3372-SMS
{
    <#
    .SYNOPSIS
        Send SMS from E3372 Modem
    .DESCRIPTION
        Long description
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        IP_Or_Hostname - Ip Address or Hostname of Modem
    .OUTPUTS
        Output (if any)
    .NOTES
        General notes
    #>

    [CmdletBinding()]
    param (
  
        [Parameter(Mandatory=$true, HelpMessage='IP Address or Hostname of the Modem')]
        [ValidateNotNullOrEmpty()]
        [string]
        $IP_Or_Hostname,

        [Parameter(Mandatory=$true, HelpMessage='Phone Number to Send Messages to')]
        [ValidateNotNullOrEmpty()]
        [string]
        $PhoneNumber,

        [Parameter(Mandatory=$true, HelpMessage='SMS Message Content')]
        [ValidateNotNullOrEmpty()]
        [string]
        $MsgConent

    )

    # api path
    $API_Path = "/api/sms/send-sms"

    # post data
    $data = "<request><Index>-1</Index><Phones><Phone>$PhoneNumber</Phone></Phones><Sca></Sca><Content>$MsgConent</Content><Length>-1</Length><Reserved>1</Reserved><Date>-1</Date></request>"

    # obtain response from api request to e3372 modem
    $response = (New-API-Request-InternalFunction -IP_Or_Hostname $IP_Or_Hostname -API_Path $API_Path -PostData $data)

    # Check response for errors
    if($response.response -eq "OK")
    {
        return $true
    }
    else 
    {
        return $false
    }
}

function Get-E3372-SMS
{
    <#
    .SYNOPSIS
        Get SMS from E3372 Modem
    .DESCRIPTION
        Long description
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Hashtable of All Messages from E3372 Modem
    .NOTES
        General notes
    #>

    [CmdletBinding()]
    param (
  
        [Parameter(Mandatory=$true, HelpMessage='IP Address or Hostname of the Modem')]
        [ValidateNotNullOrEmpty()]
        [string]
        $IP_Or_Hostname,

        [switch]
        $SentMessages

    )

    $SentMsgBox = 2 # This is the box type for sent messages
    $RecvMsgBox = 1 # This is the box type for received messages
    $BoxType = $RecvMsgBox # Set to default - received messages

    if($SentMessages)
    {
        $BoxType = $SentMsgBox
    }

    # api path
    $API_Path = "/api/sms/sms-list"

    # post data
    $data = "<request><PageIndex>1</PageIndex><ReadCount>20</ReadCount><BoxType>$BoxType</BoxType><SortType>0</SortType><Ascending>0</Ascending><UnreadPreferred>1</UnreadPreferred></request>"

    # obtain response from api request to e3372 modem
    $response = (New-API-Request-InternalFunction -IP_Or_Hostname $IP_Or_Hostname -API_Path $API_Path -PostData $data)

    # Create return object
    $return = New-Object System.Collections.ArrayList

    # Loop through each message
    foreach ($item in $response.response.messages.Message) {
        # Create a hashtable for each message
        $ht = @{}
        $ht.Index = $item.Index
        $ht.Phone = $item.Phone
        $ht.Content = $item.Content
        $ht.Date = $item.Date
        # Get uniqe id for message based on all the above items as a hash
        $MsgHash = Get-Hash -text ($ht.Index+$ht.Phone+$ht.Content+$ht.Date)
        $ht.MsgHash = $MsgHash
        # Add the hashtable to the new collection
        $return.Add($ht) | Out-Null
    }

    # Return the collection of hashtables empty or otherwise
    return $return
}

function Remove-E3372-SMS
{
    <#
    .SYNOPSIS
        Remove SMS from E3372 Modem
    .DESCRIPTION
        Long description
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Output (if any)
    .NOTES
        General notes
    #>

    [CmdletBinding()]
    param (
  
        [Parameter(Mandatory=$true, HelpMessage='IP Address or Hostname of the Modem')]
        [ValidateNotNullOrEmpty()]
        [string]
        $IP_Or_Hostname,

        [Parameter(Mandatory=$true, HelpMessage='Index of the SMS to remove')]
        [ValidateRange(40000,49999)]
        [int]
        $MessageIndex

    )

    # api path
    $API_Path = "/api/sms/delete-sms"

    # post data
    $data = "<request><Index>$MessageIndex</Index></request>"

    # obtain response from api request to e3372 modem
    $response = (New-API-Request-InternalFunction -IP_Or_Hostname $IP_Or_Hostname -API_Path $API_Path -PostData $data)

    # Check response for errors
    if($response.response -eq "OK")
    {
        return $true
    }
    else 
    {
        return $false
    }
}

#########################################################################################
# Enable or Disable 4G Modem
#########################################################################################
function Set-E3372-4G-Modem
{
    <#
    .SYNOPSIS
        Set 4G Modem on E3372 Modem Status
    .DESCRIPTION
        Long description
    .EXAMPLE
        PS C:\> <example usage>
        Explanation of what the example does
    .INPUTS
        Inputs (if any)
    .OUTPUTS
        Output (if any)
    .NOTES
        General notes
    #>

    [CmdletBinding()]
    param (
  
        [Parameter(Mandatory=$true, HelpMessage='IP Address or Hostname of the Modem')]
        [ValidateNotNullOrEmpty()]
        [string]
        $IP_Or_Hostname,

        [Parameter(Mandatory=$true, HelpMessage='Enable or Disable 4G Modem')]
        [bool]
        $Enable

    )

    # Create Variable for API Data
    [int]$ModemStatus = 2

    if($Enable)
    {
        $ModemStatus = 1
    }
    else
    {
        $ModemStatus = 0
    }

    # api path
    $API_Path = "/api/dialup/mobile-dataswitch"

    # post data
    $data = "<request><dataswitch>$ModemStatus</dataswitch></request>"

    # obtain response from api request to e3372 modem
    $response = (New-API-Request-InternalFunction -IP_Or_Hostname $IP_Or_Hostname -API_Path $API_Path -PostData $data)

    # Check response for errors
    if($response.response -eq "OK")
    {
        return $true
    }
    else 
    {
        return $false
    }
}

<#

    Usage:

    Tested Working:

    - SMS Management - 

    Send SMS Message - returns true if successful
    $result = New-E3372-SMS -IP_Or_Hostname "192.168.8.1" -PhoneNumber "0123456789" -MsgConent "Test Message"

    Get SMS Messages - returns a collection of hashtables
    $result = Get-E3372-SMS -IP_Or_Hostname "192.168.8.1"
    
    Get SMS Messages that were SENT from Modem- returns a collection of hashtables
    $result = Get-E3372-SMS -IP_Or_Hostname "192.168.8.1" -SentMessages

    Remove SMS Message - returns true if successful
    Remove-E3372-SMS -IP_Or_Hostname "192.168.8.1" -MessageIndex 40002

    Remove All Sent Messages 
    Get-E3372-SMS -IP_Or_Hostname "192.168.8.1" -SentMessages | ForEach-Object {Remove-E3372-SMS -IP_Or_Hostname "192.168.8.1" -MessageIndex $_.Index}
    
    - 4G Modem Management -

    Set 4G Modem on E3372 Modem Status

    Disable 4G Modem
    Set-E3372-4G-Modem -IP_Or_Hostname "192.168.8.1" -Enable $false

    Enable 4G Modem
    Set-E3372-4G-Modem -IP_Or_Hostname "192.168.8.1" -Enable $true

#>





