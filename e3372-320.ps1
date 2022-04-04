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
function New-SessionInfo
{
    
    param
    (
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    # Create a new session

    # Create a returnable variable
    [hashtable]$ConInfo = @{}
    # Create uri for the API call
    $url = "http://$ModemIpAddress/api/webserver/SesTokInfo"
    # Create a new HTTP request object
    [xml]$response = (Invoke-RestMethod -Uri $url -Method Get )
    # Get the token from the response
    $token =$response.response.TokInfo
    # Get the session ID from the response
    $key = $response.response.SesInfo
    # Add the session ID and token to the returnable variable
    $ConInfo["token"] = $token
    $ConInfo["SessionID"] = $key
    # Return the returnable variable
    return $ConInfo
}

function New-APIGetRequest
{
    param
    (
        $url,
        $endpoint
    )

    $uri = "http://$url/$endpoint"

    $ConInfo = new-SessionInfo $url

     # Create HTTP header with token
     $headers = @{
        "__RequestVerificationToken" = $ConInfo["token"]
    }

    # Create a new cookie container and add the session ID
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $cookie = New-Object System.Net.Cookie 
    $cookie.Name = "SessionID"
    $cookie.Value = $ConInfo["SessionID"]
    $cookie.Domain = $ModemsIPAddress
    $session.Cookies.Add($cookie)

    # Create a new HTTP request object
    [xml]$response = (Invoke-RestMethod -Uri $uri -Method Get -ContentType "text/xml" -Headers $headers -WebSession $session)

    # Return the response
    return $response
}

<#
    Create a new POST API Call
#>
function New-APIPostRequest
{

    param(
        $url, # URL of the API call
        $endpoint, # Endpoint of the API call
        $data # Data to be sent to the API call
    )

    # Create a uri for the API call
    $uri = "http://$url/$endpoint"

    # Obtain session token and session ID
    $ConInfo = New-SessionInfo -ModemIpAddress $ModemsIPAddress

    # Create HTTP header with token
    $headers = @{
        "__RequestVerificationToken" = $ConInfo["token"]
    }

    # Create a new cookie container and add the session ID
    $session = New-Object Microsoft.PowerShell.Commands.WebRequestSession
    $cookie = New-Object System.Net.Cookie 
    $cookie.Name = "SessionID"
    $cookie.Value = $ConInfo["SessionID"]
    $cookie.Domain = $ModemsIPAddress
    $session.Cookies.Add($cookie)

    # Create a new HTTP request object
    [xml]$response = (Invoke-RestMethod -Uri $uri -Method Post -ContentType "text/xml" -Headers $headers -body $data -WebSession $session)

    # Return the response
    return $response
}

Function Clear-DeviceTrafficStats
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_ClearTrafficStats = "api/monitoring/clear-traffic"
    $data = "<request><ClearTraffic>1</ClearTraffic></request>"
    [xml]$response = (New-APIPostRequest -url $ModemsIPAddress -endpoint $API_ClearTrafficStats -data $data)
    return $response
}
function Set-DeviceInternetOnline
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceInternetOnline = "api/dialup/mobile-dataswitch"
    $data = "<request><dataswitch>1</dataswitch></request>"
    [xml]$response = (New-APIPostRequest -url $ModemsIPAddress -endpoint $API_DeviceInternetOnline -data $data)
    return $response
}

function Set-DeviceInternetOffline
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceInternetOffline = "api/dialup/mobile-dataswitch"
    $data = "<request><dataswitch>0</dataswitch></request>"
    [xml]$response = (New-APIPostRequest -url $ModemsIPAddress -endpoint $API_DeviceInternetOffline -data $data)
    return $response
}


# Get a list of SMS messages from e3372-320 modem
Function Get-SMSMessages {
    
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    # API Paths - these are the API paths that are used to control the modem
    # Do not change these unless you know what you are doing
    $API_SMSList = "api/sms/sms-list"

    # Data to be sent to the API call - obtain 20 message from the modem
    $data = "<request><PageIndex>1</PageIndex><ReadCount>20</ReadCount><BoxType>1</BoxType><SortType>0</SortType><Ascending>0</Ascending><UnreadPreferred>1</UnreadPreferred></request>"

    # return xml response
    [xml]$response = (New-APIPostRequest -url $ModemIpAddress -endpoint $API_SMSList -data $data)
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
    $API_SendSMS = "api/sms/send-sms"

    # Data to be sent to the API call
    $data = "<?xml version='1.0' encoding='UTF-8'?><request><Index>-1</Index><Phones><Phone>$PhoneNumber</Phone></Phones><Sca></Sca><Content>$Message</Content><Length>-1</Length><Reserved>1</Reserved><Date>-1</Date></request>"
    [xml]$response = (New-APIPostRequest -url $ModemsIPAddress -endpoint $API_SendSMS -data $data)
    return $response
}

function Get-DeviceInformation
{

    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceInformation = "api/device/information"

    [xml]$response = (New-APIGetRequest -url $ModemsIPAddress -endpoint $API_DeviceInformation)
    return $response

}

function  Get-DeviceStatus 
{

    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceStatus = "api/monitoring/status"

    [xml]$response = (New-APIGetRequest -url $ModemsIPAddress -endpoint $API_DeviceStatus)
    return $response
}

function Get-DeviceNotifications
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceNotifications = "api/monitoring/check-notifications"

    [xml]$response = (New-APIGetRequest -url $ModemsIPAddress -endpoint $API_DeviceNotifications)
    return $response
}

function Get-DeviceNetworkInfo 
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )
    
    $API_DeviceNetworkInfo = "api/net/current-plmn"

    [xml]$response = (New-APIGetRequest -url $ModemsIPAddress -endpoint $API_DeviceNetworkInfo)
    return $response
}

function Get-DeviceTrafficStats
{
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    $API_DeviceTrafficStats = "api/monitoring/traffic-statistics"

    [xml]$response = (New-APIGetRequest -url $ModemsIPAddress -endpoint $API_DeviceTrafficStats)
    return $response
}

# Get Stored SMS Messages

#$output = Get-SMSMessages -ModemIpAddress $ModemsIPAddress
#$output.innerXML

#########################

# Send a SMS message to a phone number

#$output = New-SMSMessage -ModemIpAddress $ModemsIPAddress -PhoneNumber "0123456789" -Message "Hello World"
#$output.innerXML

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
#$output.innerXML

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
