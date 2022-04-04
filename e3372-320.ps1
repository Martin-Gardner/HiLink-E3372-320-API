<#
    
    HiLink E3372 API Script

    Created: 01/04/2022
    Updated: 01/04/2022

    Author: Martin Gardner

    Notes:
    01-04-2022 - Added support for HiLink E3372
    01-04-2022 - Fixed issue with HiLink E3372 sms-list api call error 125003 
                 This was caused by not passing the cookie the correct way
    01-04-2022 - Added support for sending sms - will add support for sending sms to multiple numbers

#>

# Ip address of the HiLink E3372
$ModemsIPAddress = "192.168.8.1"



<#
    This created a new session with the HiLink E3372.
    
    This is called every time any of the API calls are made.
    
    It obtains a session ID and stores it in the $SessionID variable.
    It obtains a token and stores it in the $Token variable.
#>
function New-E3372_Api_Request
{
    param
    (
        $url,           # IP or hostname of the modem
        $endpoint,      # API endpoint to call minus the leading /
        $data = ""      # Optional data to send to the endpoint if this is a POST
    )

    # Check if function was called with a URL
    if([string]::IsNullOrEmpty($url))
    {
        throw "URL is required - eg 192.168.8.1"
    }

    # Check if function was called with an endpoint
    if([string]::IsNullOrEmpty($endpoint))
    {   
        throw "Endpoint is required - eg /api/sms/sms-list"
    }

    # Get Session and Token for API call
    $TokenResponse = (Invoke-RestMethod -Uri "http://$url/api/webserver/SesTokInfo" -Method Get )

    # Parse the response to get the session and token
    $SessionKey = $TokenResponse.response.TokInfo
    $SessionID  = $TokenResponse.response.SesInfo

    # Check if the session and token were returned
    if([String]::IsNullOrEmpty($SessionID) -or [String]::IsNullOrEmpty($SessionKey))
    {
        throw "Failed to get session ID and key"
    }

    # Create HTTP header with token

    $headers = @{"__RequestVerificationToken" = $SessionKey}

    # Create a new cookie container and add the session ID
    # NOTE: this is the way to fix invalid token issue 
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $cookie = New-Object System.Net.Cookie 
    $cookie.Name = "SessionID"
    $cookie.Value = $SessionID
    $cookie.Domain = $ModemsIPAddress
    $session.Cookies.Add($cookie)

    # Build Empty HTTP
    [xml]$response = ""

    # Check to see if this is a POST or GET
    if($data -eq "")
    {
        # This is a GET request
        [xml]$response = (Invoke-RestMethod -Uri "http://$url$endpoint" -Method Get -ContentType "text/xml" -Headers $headers -WebSession $session)
    }
    else 
    {
        # This is a POST request
        [xml]$response = (Invoke-RestMethod -Uri "http://$url$endpoint" -Method Post -ContentType "text/xml" -Headers $headers -WebSession $session -Body $data)
    }

    # Check to see if the response was successful
    # Check to see if response contained error code
    $api_errorcheck = $response.error.code
    $api_error = ""
    # Is there an error?
    if(!([string]::IsNullOrEmpty($api_errorcheck)))
    {
        # Ok there is an error let's get it
        switch ($api_errorcheck) {
            "-1"     { $api_error = "system not available - $api_errorcheck"}
            "100002" { $api_error = "not supported by firmware or incorrect API path - $api_errorcheck"}
            "100003" { $api_error = "unauthorized - $api_errorcheck"}
            "100004" { $api_error = "system busy - $api_errorcheck"}
            "100005" { $api_error = "unknown error - $api_errorcheck"}
            "100006" { $api_error = "invalid parameter - $api_errorcheck"}
            "100009" { $api_error = "write error - $api_errorcheck"}
            "103002" { $api_error = "unknown error - $api_errorcheck"}
            "103015" { $api_error = "unknown error - $api_errorcheck"}
            "108001" { $api_error = "invalid username - $api_errorcheck"}
            "108002" { $api_error = "invalid password - $api_errorcheck"}
            "108003" { $api_error = "user already logged in - $api_errorcheck"}
            "108006" { $api_error = "invalid username or password - $api_errorcheck"}
            "108007" { $api_error = "invalid username} password} or session timeout - $api_errorcheck"}
            "110024" { $api_error = "battery charge less than 50% - $api_errorcheck"}
            "111019" { $api_error = "no network response - $api_errorcheck"}
            "111020" { $api_error = "network timeout - $api_errorcheck"}
            "111022" { $api_error = "network not supported - $api_errorcheck"}
            "113018" { $api_error = "system busy - $api_errorcheck"}
            "114001" { $api_error = "file already exists - $api_errorcheck"}
            "114002" { $api_error = "file already exists - $api_errorcheck"}
            "114003" { $api_error = "SD card currently in use - $api_errorcheck"}
            "114004" { $api_error = "path does not exist - $api_errorcheck"}
            "114005" { $api_error = "path too long - $api_errorcheck"}
            "114006" { $api_error = "no permission for specified file or directory - $api_errorcheck"}
            "115001" { $api_error = "unknown error - $api_errorcheck"}
            "117001" { $api_error = "incorrect WiFi password - $api_errorcheck"}
            "117004" { $api_error = "incorrect WISPr password - $api_errorcheck"}
            "120001" { $api_error = "voice busy - $api_errorcheck"}
            "125001" { $api_error = "invalid token - $api_errorcheck"}
            default  { "Unkown error retuned from API - $api_errorcheck" }
        }
    }

    # Check to see if there was an error
    if(!([String]::IsNullOrEmpty($api_error)))
    {
        throw "Error accessing http://$url$endpoint - $api_error"
    }

    # Return the response
    return $response
}

Function Clear-DeviceTrafficStats
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_ClearTrafficStats = "/api/monitoring/clear-traffic"
    $data = "<request><ClearTraffic>1</ClearTraffic></request>"
    [xml]$response = (New-E3372_Api_Request -url $ModemsIPAddress -endpoint $API_ClearTrafficStats -data $data)
    return $response
}
function Set-DeviceInternetOnline
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceInternetOnline = "/api/dialup/mobile-dataswitch"
    $data = "<request><dataswitch>1</dataswitch></request>"
    [xml]$response = (New-E3372_Api_Request -url $ModemsIPAddress -endpoint $API_DeviceInternetOnline -data $data)
    return $response
}

function Set-DeviceInternetOffline
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceInternetOffline = "/api/dialup/mobile-dataswitch"
    $data = "<request><dataswitch>0</dataswitch></request>"
    [xml]$response = (New-E3372_Api_Request -url $ModemsIPAddress -endpoint $API_DeviceInternetOffline -data $data)
    return $response
}


# Get a list of SMS messages from e3372-320 modem
Function Get-SMSMessages {
    
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    # API Paths - these are the API paths that are used to control the modem
    # Do not change these unless you know what you are doing
    $API_SMSList = "/api/sms/sms-list"

    # Data to be sent to the API call - obtain 20 message from the modem
    $data = "<request><PageIndex>1</PageIndex><ReadCount>20</ReadCount><BoxType>1</BoxType><SortType>0</SortType><Ascending>0</Ascending><UnreadPreferred>1</UnreadPreferred></request>"

    # return xml response
    [xml]$response = (New-E3372_Api_Request -url $ModemIpAddress -endpoint $API_SMSList -data $data)
    return $response
}

# Send a SMS message to a phone number
Function New-SMSMessage {
    
    param(
        $ModemIpAddress, # Ip address of the HiLink E3372
        $PhoneNumber, # Phone number to send the SMS to - should allow ; between numbers for multiple numbers
        $Message # Message to send
    )

    # API Paths - these are the API paths that are used to control the modem
    # Do not change these unless you know what you are doing
    $API_SendSMS = "/api/sms/send-sms"

    # Data to be sent to the API call
    $data = "<request><Index>-1</Index><Phones><Phone>$PhoneNumber</Phone></Phones><Sca></Sca><Content>$Message</Content><Length>-1</Length><Reserved>1</Reserved><Date>-1</Date></request>"
    [xml]$response = (New-E3372_Api_Request -url $ModemsIPAddress -endpoint $API_SendSMS -data $data)
    return $response
}

function Get-DeviceInformation
{

    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceInformation = "/api/device/information"

    [xml]$response = (New-E3372_Api_Request -url $ModemsIPAddress -endpoint $API_DeviceInformation)
    return $response

}

function  Get-DeviceStatus 
{

    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceStatus = "/api/monitoring/status"

    [xml]$response = (New-E3372_Api_Request -url $ModemsIPAddress -endpoint $API_DeviceStatus)
    return $response
}

function Get-DeviceNotifications
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceNotifications = "/api/monitoring/check-notifications"

    [xml]$response = (New-E3372_Api_Request -url $ModemsIPAddress -endpoint $API_DeviceNotifications)
    return $response
}

function Get-DeviceNetworkInfo 
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )
    
    $API_DeviceNetworkInfo = "/api/net/current-plmn"

    [xml]$response = (New-E3372_Api_Request -url $ModemsIPAddress -endpoint $API_DeviceNetworkInfo)
    return $response
}

function Get-DeviceTrafficStats
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceTrafficStats = "/api/monitoring/traffic-statistics"

    [xml]$response = (New-E3372_Api_Request -url $ModemsIPAddress -endpoint $API_DeviceTrafficStats)
    return $response
}

# Get Stored SMS Messages

#$output = Get-SMSMessages -ModemIpAddress $ModemsIPAddress
#$output.innerXML

#########################

# Send a SMS message to a phone number

$output = New-SMSMessage -ModemIpAddress $ModemsIPAddress -PhoneNumber "01234567890" -Message "Hello World"
$output.innerXML

#########################

# Get Device Information

#$output = Get-DeviceInformation -ModemIpAddress $ModemsIPAddress
#$output.innerXML

#########################

# Get Device Status

#$output = Get-DeviceStatus -ModemIpAddress $ModemsIPAddress
#$output.innerXML

#########################

# Get Device Notification

#$output = Get-DeviceNotifications -ModemIpAddress $ModemsIPAddress
#$output.innerXML

#########################

# Get Device Network Information

#$output = Get-DeviceNetworkInfo -ModemIpAddress $ModemsIPAddress
#$output.InnerXml

#########################

# Set Device Internet Offline

#$output = Set-DeviceInternetOffline -ModemIpAddress $ModemsIPAddress
#$output.innerXML

#########################

# Set Device Internet Online

#$output = Set-DeviceInternetOnline -ModemIpAddress $ModemsIPAddress
#$output.innerXML

#########################

# Get Device Traffic Statistics

#$output = Get-DeviceTrafficStats -ModemIpAddress $ModemsIPAddress
#$output.innerXML
