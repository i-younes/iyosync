$CHANGE_TYPE_ADD = "Add"
$CHANGE_TYPE_UPDATE = "Update"
$CHANGE_TYPE_DELETE = "Delete"
$CHANGE_TYPE_NONE = "None"

$SOURCE_ENTRIES_FILE = "D:\iyo\iyosync\sourceEntries.json"
$TARGET_CSV_FILE = "D:\iyo\iyosync\target.csv"

$SERVER = "192.168.0.10"
$ACCOUNT="cn=administrateur,cn=users,dc=iyo,dc=local"
$PASSWORD="PA`$`$w0rd"

$SEARCH_BASE = "ou=it,dc=iyo,dc=local"
$SEARCH_FILTER = "(objectClass=user)"
$SEARCH_ATTRIBUTES = "givenName","sn","displayName"

$SOURCE_ANCHOR = "distinguishedName"
$SOURCE_FILTER = "STARTSWITH([givenName],Isma)"
$SOURCE_MAPPINGS = @{distinguishedName="dn"; givenName="firstName"; sn="lastName"; displayName="displayName"}
$SOURCE_TRANSFORMATIONS = @{lastName="UPPER([sn])"}

Clear-Host
Write-Host -ForegroundColor Green (Get-Date) "- Starting the import ..."

$credentials = New-Object System.Net.NetworkCredential($ACCOUNT, $PASSWORD)
$null = [System.Reflection.Assembly]::LoadWithPartialName("System.DirectoryServices.Protocols")  
$directoryIdentifier = New-Object System.DirectoryServices.Protocols.LdapDirectoryIdentifier($SERVER)
$ldapConnection = New-Object System.DirectoryServices.Protocols.LdapConnection($directoryIdentifier, $credentials)
$ldapConnection.SessionOptions.ProtocolVersion = 3
$ldapConnection.AuthType = [System.DirectoryServices.Protocols.AuthType]::Basic
$ldapConnection.Bind()

$searchRequest = new-object System.DirectoryServices.Protocols.SearchRequest
$searchRequest.DistinguishedName = $SEARCH_BASE
$searchRequest.Scope = "Subtree"
$searchRequest.Filter = $SEARCH_FILTER
foreach($attribute in $SEARCH_ATTRIBUTES){
    $null = $searchRequest.Attributes.Add($attribute)
}

$response = $ldapConnection.SendRequest($searchRequest)

$oldSourceEntries = @()
if(Test-Path $SOURCE_ENTRIES_FILE){
    Write-Host -ForegroundColor Green (Get-Date) "- Deleting file $SOURCE_ENTRIES_FILE ..."
    $oldSourceEntries = Get-Content $SOURCE_ENTRIES_FILE -Raw | ConvertFrom-Json
}

$importChanges = @()
$sourceEntries = @()
foreach($responseEntry in $response.entries){
    $sourceEntry = New-Object -TypeName PSObject
    $sourceEntry | Add-Member -MemberType NoteProperty -Name distinguishedName -Value $responseEntry.DistinguishedName
    
    foreach($attributeName in $SEARCH_ATTRIBUTES){
        if($null -ne $responseEntry.Attributes[$attributeName]){
            $sourceEntry | Add-Member -MemberType NoteProperty -Name $attributeName -Value $responseEntry.Attributes[$attributeName][0]
        }
    }

    $sourceEntries += $sourceEntry
    
    $importChange = New-Object PSObject
    $existingEntry = $oldSourceEntries | Where-Object{$_.$SOURCE_ANCHOR -eq $sourceEntry.$SOURCE_ANCHOR}
    if($existingEntry){
        if(($sourceEntry | ConvertTo-Json -Compress) -eq ($existingEntry | ConvertTo-Json -Compress)){         
            $importChange | Add-Member -MemberType NoteProperty -Name "ChangeType" -Value $CHANGE_TYPE_NONE
            $importChange | Add-Member -MemberType NoteProperty -Name "OldSourceEntry" -Value $existingEntry
        }
        else{
            $importChange | Add-Member -MemberType NoteProperty -Name "ChangeType" -Value $CHANGE_TYPE_UPDATE
            $importChange | Add-Member -MemberType NoteProperty -Name "OldSourceEntry" -Value $existingEntry
        }    
    }
    else{
        $importChange = New-Object PSObject
        $importChange | Add-Member -MemberType NoteProperty -Name "ChangeType" -Value $CHANGE_TYPE_ADD
        $importChange | Add-Member -MemberType NoteProperty -Name "OldSourceEntry" -Value ""   
    }
    $importChange | Add-Member -MemberType NoteProperty -Name "SourceEntry" -Value $sourceEntry
    $importChanges += $importChange
}

foreach($oldSourceEntry in $oldSourceEntries){
    $existingEntry = $sourceEntries | Where-Object{$_.$SOURCE_ANCHOR -eq $oldSourceEntry.$SOURCE_ANCHOR}
    if(!$existingEntry){
        $importChange = New-Object PSObject
        $importChange | Add-Member -MemberType NoteProperty -Name "ChangeType" -Value $CHANGE_TYPE_DELETE
        $importChange | Add-Member -MemberType NoteProperty -Name "OldSourceEntry" -Value $oldSourceEntry
        $importChange | Add-Member -MemberType NoteProperty -Name "SourceEntry" -Value $existingEntry
        $importChanges += $importChange
    }
}

$importChanges.SourceEntry | ConvertTo-Json | Set-Content -Encoding UTF8 -Path $SOURCE_ENTRIES_FILE

$targetEntries = @()
foreach($importChange in $importChanges){
    $sourceEntry = $importChange.SourceEntry
    if($sourceEntry.ChangeType -eq $CHANGE_TYPE_DELETE){
        continue
    }

    if($SOURCE_FILTER -like "STARTSWITH*"){
        $filterProperty = $SOURCE_FILTER.Replace("STARTSWITH(","").Replace(")","").Split(',')[0].Replace("[","").Replace("]","")
        $filterPattern = $SOURCE_FILTER.Replace("STARTSWITH(","").Replace(")","").Split(',')[1]
        if($sourceEntry.$filterProperty -like "$filterPattern*"){
            Write-Host -ForegroundColor Green (Get-Date) "- Source entry filtered :" ($sourceEntry | ConvertTo-Json -Compress)
            continue
        }
    }

    $targetEntry = New-Object -TypeName PSObject
    foreach($sourceProperty in $sourceEntry.PSObject.Properties){
        $targetPropertyName = $SOURCE_MAPPINGS[$sourceProperty.Name]

        if($null -ne $SOURCE_TRANSFORMATIONS[$targetPropertyName]){
            $transformation = $SOURCE_TRANSFORMATIONS[$targetPropertyName]
            if($transformation -like "UPPER*"){
                $transformationProperty = $transformation.Replace("UPPER([","").Replace("])","")
                $targetValue = $sourceEntry.$transformationProperty.ToUpper()
                $targetEntry | Add-Member NoteProperty -Name $targetPropertyName -Value $targetValue
            }
            else{
                $targetEntry | Add-Member NoteProperty -Name $targetPropertyName -Value $sourceProperty.Value 
            }
        }
        else{
            $targetEntry | Add-Member NoteProperty -Name $targetPropertyName -Value $sourceProperty.Value
        }
    }
    $targetEntries += $targetEntry
}

if(Test-Path $TARGET_CSV_FILE){
    Write-Host -ForegroundColor Green (Get-Date) "- Deleting file $TARGET_CSV_FILE ..."
    Remove-Item $TARGET_CSV_FILE -Force
}
$targetEntries | Export-Csv -Encoding UTF8 -Path $TARGET_CSV_FILE -NoTypeInformation

Write-Host -ForegroundColor Green (Get-Date) "- End of the import ..."