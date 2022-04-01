<#
    
    HiLink E3372 API Script

    Created: 01/04/2022
    Updated: 01/04/2022

    Author: Martin Gardner

    Notes:
    01-04-2022 - Added support for HiLink E3372
    01-04-2022 - Fixed issue with HiLink E3372 sms-list api call error 125003 
                 This was caused by not passing the cookie the correct way

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
    return $coninfo
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

# Get a list of SMS messages from e3372 modem
Function Get-SMSMessages {
    param(
        $ModemIpAddress # Ip address of the HiLink E3372
    )

    # API Paths - these are the API paths that are used to control the modem
    # Do not change these unless you know what you are doing
    $API_SMSList = "api/sms/sms-list"

    # Data to be sent to the API call - obtain 20 message from the modem
    $data = "
<request>
    <PageIndex>1</PageIndex>
    <ReadCount>20</ReadCount>
    <BoxType>1</BoxType>
    <SortType>0</SortType
    ><Ascending>0</Ascending>
    <UnreadPreferred>1</UnreadPreferred>
</request>"

    # return xml response
    return $(New-APIPostRequest -url $ModemsIPAddress -endpoint $API_SMSList -data $data)
}

