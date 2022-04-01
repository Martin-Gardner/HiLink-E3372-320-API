#!/bin/bash

cmd_output=$(curl -s -X GET "http://192.168.8.1/api/webserver/SesTokInfo")

COOKIE=$(echo $cmd_output | cut -b 58-185)

TOKEN=$(echo $cmd_output | cut -b 205-236)

curl -s -X POST "http://192.168.8.1/api/sms/sms-list" -b "SessionID=$COOKIE" -H "__RequestVerificationToken: $TOKEN" -H "Content-Type: text/xml" -d "<request><PageIndex>1</PageIndex><ReadCount>10</ReadCount><BoxType>1</BoxType><SortType>0</SortType><Ascending>0</Ascending><UnreadPreferred>1</UnreadPreferred></request>"
