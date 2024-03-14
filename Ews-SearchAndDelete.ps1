<#
    MIT License

    Copyright (c) Microsoft Corporation.

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE
#>

# Version 24.03.14.1628

param (
    #[ValidateSet("Online", "Onprem")]
    #[Parameter(Mandatory = $false)]
    #[string]$Environment="Online",

    [Parameter(Position=0, Mandatory=$True, HelpMessage="The Mailbox parameter specifies the mailbox to be accessed.")]
    [ValidateNotNullOrEmpty()]
    [string]$Mailbox,

    [Parameter(Mandatory=$False, HelpMessage="The Archive parameter is a switch to search the archive mailbox (otherwise, the main mailbox is searched).")]
    [alias("SearchArchive")] [switch]$Archive,

    [Parameter(Mandatory=$False, HelpMessage="The ProcessSubfolders parameter is a switch to enable searching the subfolders of any specified folder.")]
    [switch]$ProcessSubfolders,

    [Parameter(Mandatory=$False, HelpMessage="The IncludeFolderList parameter specifies the folder(s) to be searched (if not present, then the Inbox folder will be searched).  Any exclusions override this list.")]
    $IncludeFolderList,

    [Parameter(Mandatory=$False, HelpMessage="The ExcludeFolderList parameter specifies the folder(s) to be excluded (these folders will not be searched).")]
    $ExcludeFolderList,

    [Parameter(Mandatory=$false, HelpMessage="The SearchDumpster parameter is a switch to search the recoverable items.")]
    [switch]$SearchDumpster,

    [Parameter(Mandatory=$False, HelpMessage="The MessageClass parameter specifies the message class of the items being searched.")]
    [ValidateNotNullOrEmpty()]
    [string]$MessageClass,

    [Parameter(Mandatory=$false, HelpMessage="The CreatedBefore parameter specifies only messages created before this date will be searched.")]
    [DateTime]$CreatedBefore,

    [Parameter(Mandatory=$false, HelpMessage="The CreatedAfter parameter specifies only messages created after this date will be searched.")]
    [DateTime]$CreatedAfter,

    [Parameter(Mandatory=$False, HelpMessage="The Subject parameter specifies the subject string used by the search.")]
    [string]$Subject,

    [Parameter(Mandatory=$False, HelpMessage="The Sender parameter specifies the sender email address used by the search.")]
    [string]$Sender,

    [Parameter(Mandatory=$False, HelpMessage="The MessageBody parameter specifies the body string used by the search.")]
    [string]$MessageBody,

    [Parameter(Mandatory=$False, HelpMessage="The MessageId parameter specified the MessageId used by the search.")]
    [string]$MessageId,

    [Parameter(Mandatory=$False, HelpMessage="The DeleteContent parameter is a switch to delete the items found in the search results (moved to Deleted Items).")]
    [switch]$DeleteContent,

    [Parameter(Mandatory=$False, HelpMessage="The HardDelete parameter is a switch to hard-delete the items found in the search results (otherwise, they'll be moved to Deleted Items).")]
    [switch]$HardDelete,

    [ValidateSet("Global", "USGovernmentL4", "USGovernmentL5", "ChinaCloud")]
    [Parameter(Mandatory = $false)]
    [string]$AzureEnvironment = "Global",

    [Parameter(Mandatory = $false)]
    [ValidateRange(1, 2147483)]
    [int]$TimeoutSeconds = 300,

    [ValidateScript({ Test-Path $_ })]
    [Parameter(Mandatory = $false)]
    [string]$DLLPath,

    [Parameter(Mandatory=$False, HelpMessage="The OAuthClientId parameter is the Azure Application Id that this script uses to obtain the OAuth token.  Must be registered in Azure AD.")]
    [string]$OAuthClientId = "",

    [Parameter(Mandatory=$False, HelpMessage="The OAuthTenantId parameter is the tenant Id where the application is registered (Must be in the same tenant as mailbox being accessed).")]
    [string]$OAuthTenantId = "",

    [Parameter(Mandatory=$False, HelpMessage="The OAuthRedirectUri parameter is the redirect Uri of the Azure registered application.")]
    [string]$OAuthRedirectUri = "https://login.microsoftonline.com/common/oauth2/nativeclient",

    [Parameter(Mandatory=$False, HelpMessage="The OAuthSecretKey parameter is the the secret for the registered application.")]
    [SecureString]$OAuthClientSecret = "",

    [Parameter(Mandatory=$False, HelpMessage="The OAuthCertificate parameter is the certificate for the registered application. Certificate auth requires MSAL libraries to be available.")]
    $OAuthCertificate = $null,
    [ValidateScript({ Test-Path $_ })] [Parameter(Mandatory = $true, HelpMessage="The OutputPath parameter specifies the path for the EWS usage report.")] [string] $OutputPath,

    [Parameter(Mandatory=$False, HelpMessage="The ThrottlingDelay parameter specifies the throttling delay (time paused between sending EWS requests) - note that this will be increased automatically if throttling is detected")]
    [int]$ThrottlingDelay = 0,

    [Parameter(Mandatory=$False, HelpMessage="The BatchSize parameter specifies the batch size (number of items batched into one EWS request) - this will be decreased if throttling is detected")]
    [int]$BatchSize = 200
)

begin {
    . $PSScriptRoot\..\Security\src\CVE-2023-23397\WriteFunctions.ps1
    . $PSScriptRoot\..\Shared\CertificateFunctions\Enable-TrustAnyCertificateCallback.ps1
    . $PSScriptRoot\..\Shared\OutputOverrides\Write-Host.ps1
    . $PSScriptRoot\..\Shared\OutputOverrides\Write-Verbose.ps1
    . $PSScriptRoot\..\Shared\OutputOverrides\Write-Warning.ps1
    . $PSScriptRoot\..\Shared\LoggerFunctions.ps1
    . $PSScriptRoot\..\Shared\ActiveDirectoryFunctions\Test-ADCredentials.ps1
    . $PSScriptRoot\..\Shared\AzureFunctions\Get-CloudServiceEndpoint.ps1
    . $PSScriptRoot\..\Shared\AzureFunctions\Get-NewJsonWebToken.ps1
    . $PSScriptRoot\..\Shared\AzureFunctions\Get-NewOAuthToken.ps1
    . $PSScriptRoot\..\Shared\Show-Disclaimer.ps1

    function EWSAuth {
        param(
            [string]$Environment,
            $Token,
            $EWSOnlineURL,
            $EWSServerURL
        )
        ## Create the Exchange Service object with credentials
        $Service = New-Object Microsoft.Exchange.WebServices.Data.ExchangeService([Microsoft.Exchange.WebServices.Data.ExchangeVersion]::Exchange2016)

        $Service.Timeout = $TimeoutSeconds * 1000

        if ($Environment -eq "Onprem") {
            $Service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.WebCredentials($credential.UserName, [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($credential.Password)))
        } else {
            $Service.Credentials = New-Object Microsoft.Exchange.WebServices.Data.OAuthCredentials($Token.access_token)
        }

        if ($Environment -eq "Onprem") {
            if (-not([System.String]::IsNullOrEmpty($EWSServerURL))) {
                $Service.Url = New-Object Uri($EWSServerURL)
                CheckOnpremCredentials -EWSService $Service
            } else {
                try {
                    $credentialTestResult = Test-ADCredentials -Credentials $credential
                    if ($credentialTestResult.CredentialsValid) {
                        Write-Host "Credentials validated successfully." -ForegroundColor Green
                    } elseif ($credentialTestResult.CredentialsValid -eq $false) {
                        Write-Host "Credentials that were provided are incorrect." -ForegroundColor Red
                        exit
                    } else {
                        Write-Host "Credentials couldn't be validated. Trying to use the credentials anyway." -ForegroundColor Yellow
                    }

                    if (($credentialTestResult.UsernameFormat -eq "downlevel") -or
                    ($credentialTestResult.UsernameFormat -eq "local")) {
                        Write-Host "Username: $($Credential.UserName) was passed in $($credentialTestResult.UsernameFormat) format" -ForegroundColor Red
                        Write-Host "You must use the -EWSServerURL parameter if the username is not in UPN (username@domain) format." -ForegroundColor Red
                        exit
                    }

                    $redirectionCallback = {
                        param([string]$url)
                        return $url.ToLower().StartsWith($autoDSecureName)
                    }

                    $Service.AutodiscoverUrl($Credential.UserName, $redirectionCallback)
                } catch [Microsoft.Exchange.WebServices.Data.AutodiscoverLocalException] {
                    Write-Host "Unable to locate the Autodiscover service by using username $($Credential.UserName)" -ForegroundColor Red
                    Write-Host "A reason could be that the username that was passed uses a domain which is not an accepted domain by Exchange Server." -ForegroundColor Red
                    Write-Host "You must use the -EWSServerURL parameter if the Autodiscover service cannot be located." -ForegroundColor Red
                    Write-Host "Inner Exception:`n$_" -ForegroundColor Red
                    exit
                } catch [System.FormatException] {
                    # We should no longer get here as we are validating the username format above, however, keeping this as failsafe for now
                    Write-Host "Username: $($Credential.UserName) was passed in an unexpected format" -ForegroundColor Red
                    Write-Host "Please try again or use the -EWSServerURL parameter to provide the EWS url." -ForegroundColor Red
                    Write-Host "Inner Exception:`n$_" -ForegroundColor Red
                    exit
                } catch {
                    Write-Host "Unable to make Autodiscover call to fetch EWS endpoint details. Please make sure you have enter valid credentials. Inner Exception`n`n$_" -ForegroundColor Red
                    exit
                }
            }
        } else {
            $Service.Url = $Script:ewsOnlineURL
        }
        $Service.HttpHeaders.Add("X-AnchorMailbox", $Mailbox)
        $Service.ImpersonatedUserId = New-Object Microsoft.Exchange.WebServices.Data.ImpersonatedUserId([Microsoft.Exchange.WebServices.Data.ConnectingIdType]::SmtpAddress, $Mailbox)
        return $Service
    }

    function CheckTokenExpiry {
        param(
            $ApplicationInfo,
            [ref]$EWSService,
            [ref]$Token,
            [string]$Environment,
            $EWSOnlineURL,
            $EWSOnlineScope,
            $AzureADEndpoint
        )

        # if token is going to expire in next 5 min then refresh it
        if ($null -eq $script:tokenLastRefreshTime -or $script:tokenLastRefreshTime.AddMinutes(55) -lt (Get-Date)) {
            $createOAuthTokenParams = @{
                TenantID                       = $ApplicationInfo.TenantID
                ClientID                       = $ApplicationInfo.ClientID
                Endpoint                       = $AzureADEndpoint
                CertificateBasedAuthentication = (-not([System.String]::IsNullOrEmpty($ApplicationInfo.CertificateThumbprint)))
                Scope                          = $EWSOnlineScope
            }

            # Check if we use an app secret or certificate by using regex to match Json Web Token (JWT)
            if ($ApplicationInfo.AppSecret -match "^([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)") {
                $jwtParams = @{
                    CertificateThumbprint = $ApplicationInfo.CertificateThumbprint
                    CertificateStore      = $CertificateStore
                    Issuer                = $ApplicationInfo.ClientID
                    Audience              = "$AzureADEndpoint/$($ApplicationInfo.TenantID)/oauth2/v2.0/token"
                    Subject               = $ApplicationInfo.ClientID
                }
                $jwt = Get-NewJsonWebToken @jwtParams

                if ($null -eq $jwt) {
                    Write-Host "Unable to sign a new Json Web Token by using certificate: $($ApplicationInfo.CertificateThumbprint)" -ForegroundColor Red
                    exit
                }

                $createOAuthTokenParams.Add("Secret", $jwt)
            } else {
                $createOAuthTokenParams.Add("Secret", $ApplicationInfo.AppSecret)
            }

            $oAuthReturnObject = Get-NewOAuthToken @createOAuthTokenParams
            if ($oAuthReturnObject.Successful -eq $false) {
                Write-Host ""
                Write-Host "Unable to refresh EWS OAuth token. Please review the error message below and re-run the script:" -ForegroundColor Red
                Write-Host $oAuthReturnObject.ExceptionMessage -ForegroundColor Red
                exit
            }
            Write-Host "Obtained a new token" -ForegroundColor Green
            $Token.Value = $oAuthReturnObject.OAuthToken
            $script:tokenLastRefreshTime = $oAuthReturnObject.LastTokenRefreshTime
            #$Script:EWSToken = $oAuthReturnObject.OAuthToken.access_token
            $Script:ewsService = EWSAuth -Environment $Environment -Token $Token.Value -EWSOnlineURL $Script:ewsOnlineURL
        } else {
            return $Script:Ewsserv
        }
    }

    # End of CSS functions

    function LoadEWSManagedAPI {
        $path = $DLLPath

        if ([System.String]::IsNullOrEmpty($path)) {
            Write-Host "Trying to find Microsoft.Exchange.WebServices.dll in the script folder"
            $path = (Get-ChildItem -LiteralPath "$PSScriptRoot\EWS" -Recurse -Filter "Microsoft.Exchange.WebServices.dll" -ErrorAction SilentlyContinue |
                    Select-Object -First 1).FullName

            if ([System.String]::IsNullOrEmpty($path)) {
                Write-Host "Microsoft.Exchange.WebServices.dll wasn't found - attempting to download it from the internet" -ForegroundColor Yellow
                $nuGetPackage = Get-NuGetPackage -PackageId "Microsoft.Exchange.WebServices" -Author "Microsoft"

                if ($nuGetPackage.DownloadSuccessful) {
                    $unzipNuGetPackage = Invoke-ExtractArchive -CompressedFilePath $nuGetPackage.NuGetPackageFullPath -TargetFolder "$PSScriptRoot\EWS"

                    if ($unzipNuGetPackage.DecompressionSuccessful) {
                        $path = (Get-ChildItem -Path $unzipNuGetPackage.FullPathToDecompressedFiles -Recurse -Filter "Microsoft.Exchange.WebServices.dll" |
                                Select-Object -First 1).FullName
                    } else {
                        Write-Host "Failed to unzip Microsoft.Exchange.WebServices.dll. Please unzip the package manually." -ForegroundColor Red
                        exit
                    }
                } else {
                    Write-Host "Failed to download Microsoft.Exchange.WebServices.dll from the internet. Please download the package manually and extract the dll. Provide the path to dll using DLLPath parameter." -ForegroundColor Red
                    exit
                }
            } else {
                Write-Host "Microsoft.Exchange.WebServices.dll was found in the script folder" -ForegroundColor Green
            }
        }

        if ($path -notlike "*Microsoft.Exchange.WebServices.dll") {
            $path = "$path\Microsoft.Exchange.WebServices.dll"
        }

        try {
            Import-Module -Name $path -ErrorAction Stop
            return $true
        } catch {
            Write-Host "Failed to import Microsoft.Exchange.WebServices.dll Inner Exception`n`n$_" -ForegroundColor Red
            exit
        }
    }
    function CreateService($smtpAddress, $impersonatedAddress = "") {
        # Creates and returns an ExchangeService object to be used to access mailboxes
        $Script:applicationInfo = @{
            "TenantID" = $OAuthTenantId
            "ClientID" = $OAuthClientId
        }

        if ([System.String]::IsNullOrEmpty($OAuthCertificate)) {
            $BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($OAuthClientSecret)
            $Secret = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
            $Script:applicationInfo.Add("AppSecret", $Secret)
        } else {
            $jwtParams = @{
                CertificateThumbprint = $OAuthCertificate
                CertificateStore      = $CertificateStore
                Issuer                = $OAuthClientId
                Audience              = "$azureADEndpoint/$OAuthTenantId/oauth2/v2.0/token"
                Subject               = $OAuthClientId
            }
            $jwt = Get-NewJsonWebToken @jwtParams

            if ($null -eq $jwt) {
                Write-Host "Unable to generate Json Web Token by using certificate: $CertificateThumbprint" -ForegroundColor Red
                exit
            }

            $Script:applicationInfo.Add("AppSecret", $jwt)
            $Script:applicationInfo.Add("CertificateThumbprint", $OAuthCertificate)
        }

        $createOAuthTokenParams = @{
            TenantID                       = $OAuthTenantId
            ClientID                       = $OAuthClientId
            Secret                         = $Script:applicationInfo.AppSecret
            Scope                          = $Script:ewsOnlineScope
            Endpoint                       = $azureADEndpoint
            CertificateBasedAuthentication = (-not([System.String]::IsNullOrEmpty($OAuthCertificate)))
        }

        #Create OAUTH token
        $oAuthReturnObject = Get-NewOAuthToken @createOAuthTokenParams
        if ($oAuthReturnObject.Successful -eq $false) {
            Write-Host ""
            Write-Host "Unable to fetch an OAuth token for accessing EWS. Please review the error message below and re-run the script:" -ForegroundColor Red
            Write-Host $oAuthReturnObject.ExceptionMessage -ForegroundColor Red
            exit
        }
        $Script:EWSToken = $oAuthReturnObject.OAuthToken
        $Script:tokenLastRefreshTime = $oAuthReturnObject.LastTokenRefreshTime
        $Script:ewsService = EWSAuth -Environment $Environment -Token $Script:EWSToken -EWSOnlineURL $Script:ewsOnlineURL
        return $Script:ewsService
    }

    function EWSPropertyType($MAPIPropertyType) {
        # Return the EWS property type for the given MAPI Property value

        switch ([Convert]::ToInt32($MAPIPropertyType, 16)) {
            0x0 { return $Null }
            0x1 { return $Null }
            0x2 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Short }
            0x1002 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::ShortArray }
            0x3 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Integer }
            0x1003 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::IntegerArray }
            0x4 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Float }
            0x1004 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::FloatArray }
            0x5 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Double }
            0x1005 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::DoubleArray }
            0x6 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Currency }
            0x1006 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::CurrencyArray }
            0x7 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::ApplicationTime }
            0x1007 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::ApplicationTimeArray }
            0x0A { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Error }
            0x0B { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Boolean }
            0x0D { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Object }
            0x100D { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::ObjectArray }
            0x14 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Long }
            0x1014 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::LongArray }
            0x1E { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::String }
            0x101E { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::StringArray }
            0x1F { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::String }
            0x101F { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::StringArray }
            0x40 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::SystemTime }
            0x1040 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::SystemTimeArray }
            0x48 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::CLSID }
            0x1048 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::CLSIDArray }
            0x102 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::Binary }
            0x1102 { return [Microsoft.Exchange.WebServices.Data.MapiPropertyType]::BinaryArray }
        }
        Write-Verbose "Couldn't match MAPI property type"
        return $Null
    }

    function InitPropList() {
        # We need to convert the properties to EWS extended properties
        if ($null -eq $script:itemPropsEws) {
            Write-Verbose "Building list of properties to retrieve"
            $script:property = @()
            foreach ($property in $ViewProperties) {
                $propDef = $null

                if ($property.StartsWith("{")) {
                    # Property definition starts with a GUID, so we expect one of these:
                    # {GUID}/name/mapiType - named property
                    # {GUID]/id/mapiType   - MAPI property (shouldn't be used when accessing named properties)

                    $propElements = $property -Split "/"
                    if ($propElements.Length -eq 2) {
                        # We expect three elements, but if there are two it most likely means that the MAPI property Id includes the Mapi type
                        if ($propElements[1].Length -eq 8) {
                            $propElements += $propElements[1].Substring(4)
                            $propElements[1] = [Convert]::ToInt32($propElements[1].Substring(0, 4), 16)
                        }
                    }
                    $guid = New-Object Guid($propElements[0])
                    $propType = EWSPropertyType($propElements[2])

                    try {
                        $propDef = New-Object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition($guid, $propElements[1], $propType)
                    } catch {
                        Write-Error "Unable to define property definitions."
                    }
                } else {
                    # Assume MAPI property
                    if ($property.ToLower().StartsWith("0x")) {
                        $property = $deleteProperty.SubString(2)
                    }
                    $propId = [Convert]::ToInt32($deleteProperty.SubString(0, 4), 16)
                    $propType = EWSPropertyType($deleteProperty.SubString(5))

                    try {
                        $propDef = New-Object Microsoft.Exchange.WebServices.Data.ExtendedPropertyDefinition($propId, $propType)
                    } catch {
                        Write-Error "Unable to define property definitions."
                    }
                }

                if ($null -ne $propDef) {
                    $script:property += $propDef
                    Write-Verbose "Added property $property to list of those to retrieve"
                } else {
                    Write-Host "Failed to parse (or convert) property $property" -ForegroundColor Red
                }
            }
        }
    }

    $script:excludedProperties = @("Schema", "Service", "IsDirty", "IsAttachment", "IsNew")
    $script:itemRetryCount = @{}
    function RemoveProcessedItemsFromList() {
        # Process the results of a batch move/copy and remove any items that were successfully moved from our list of items to move
        param (
            $requestedItems,
            $results,
            $suppressErrors = $false,
            $Items
        )

        if ($null -ne $results) {
            $failed = 0
            for ($i = 0; $i -lt $requestedItems.Count; $i++) {
                if ($results[$i].ErrorCode -eq "NoError") {
                    #LogVerbose "Item successfully processed: $($requestedItems[$i])"
                    [void]$Items.Remove($requestedItems[$i])
                } else {
                    if ( ($results[$i].ErrorCode -eq "ErrorMoveCopyFailed") -or ($results[$i].ErrorCode -eq "ErrorInvalidOperation") -or ($results[$i].ErrorCode -eq "ErrorItemNotFound") ) {
                        # This is a permanent error, so we remove the item from the list
                        [void]$Items.Remove($requestedItems[$i])
                        if (!$suppressErrors) {
                            Write-Host "Permanent error $($results[$i].ErrorCode) ($($results[$i].MessageText)) reported for item: $($requestedItems[$i].UniqueId)" -ForegroundColor Red
                        }
                    } else {
                        # This is most likely a temporary error, so we don't remove the item from the list
                        $retryCount = 0
                        if ( $script:itemRetryCount.ContainsKey($requestedItems[$i].UniqueId) )
                        { $retryCount = $script:itemRetryCount[$requestedItems[$i].UniqueId] }
                        $retryCount++
                        if ($retryCount -lt 4) {
                            #LogVerbose "Error $($results[$i].ErrorCode) ($($results[$i].MessageText)) reported for item (attempt $retryCount): $($requestedItems[$i].UniqueId)"
                            $script:itemRetryCount[$requestedItems[$i].UniqueId] = $retryCount
                        } else {
                            # We got an error 3 times in a row, so we'll admit defeat
                            [void]$Items.Remove($requestedItems[$i])
                            if (!$suppressErrors) {
                                Write-Host "Permanent error $($results[$i].ErrorCode) ($($results[$i].MessageText)) reported for item: $($requestedItems[$i].UniqueId)" -ForegroundColor Red
                            }
                        }
                    }
                    $failed++
                }
            }
        }
        if ( ($failed -gt 0) -and !$suppressErrors ) {
            Write-Host "$failed items reported error during batch request (if throttled, some failures are expected)" Yellow
        }
    }

    function ThrottledBatchDelete() {
        # Send request to move/copy items, allowing for throttling
        param (
            $ItemsToDelete,
            $BatchSize = 200,
            $SuppressNotFoundErrors = $false
        )

        if ($script:MaxBatchSize -gt 0) {
            # If we've had to reduce the batch size previously, we'll start with the last size that was successful
            $BatchSize = $script:MaxBatchSize
        }

        if ($HardDelete) {
            $deleteMode = [Microsoft.Exchange.WebServices.Data.DeleteMode]::HardDelete
        } else {
            $deleteMode = [Microsoft.Exchange.WebServices.Data.DeleteMode]::SoftDelete
        }

        $progressActivity = "Deleting items"
        $itemId = New-Object Microsoft.Exchange.WebServices.Data.ItemId("xx")
        $itemIdType = [Type] $itemId.GetType()
        $genericItemIdList = [System.Collections.Generic.List``1].MakeGenericType(@($itemIdType))

        $finished = $false
        $totalItems = $ItemsToDelete.Count
        Write-Progress -Activity $progressActivity -Status "0% complete" -PercentComplete 0

        $consecutiveErrors = 0

        while ( !$finished ) {
            $deleteIds = [Activator]::CreateInstance($genericItemIdList)
            for ([int]$i=0; $i -lt $BatchSize; $i++) {
                if ($null -ne $ItemsToDelete[$i]) {
                    $deleteIds.Add($ItemsToDelete[$i])
                }
                if ($i -ge $ItemsToDelete.Count)
                { break }
            }

            $results = $null
            try {
                #LogVerbose "Sending batch request to delete $($deleteIds.Count) items ($($ItemsToDelete.Count) remaining)"

                $results = $script:EwsService.DeleteItems( $deleteIds, $deleteMode, [Microsoft.Exchange.WebServices.Data.SendCancellationsMode]::SendToNone, $null )
                $consecutiveErrors = 0 # Reset the consecutive error count, as if we reach this point then this request succeeded with no error
            } catch {
                # We reduce the batch size if we encounter an error (sometimes throttling does not return a throttled response, this can happen if the EWS request is proxied, and the proxied request times out)
                if ($BatchSize -gt 50) {
                    $BatchSize = [int]($BatchSize * 0.8)
                    $script:MaxBatchSize = $BatchSize
                    #LogVerbose "Batch size reduced to $BatchSize"
                } else {
                    # If we've already reached a batch size of 50 or less, we set it to 10 (this is the minimum we reduce to)
                    if ($BatchSize -ne 10) {
                        $BatchSize = 10
                        #LogVerbose "Batch size set to 10"
                    }
                }
                if ( -not (Throttled) ) {
                    $consecutiveErrors++
                    try {
                        Write-Host "Unexpected error: $($Error[0].Exception.InnerException.ToString())" -ForegroundColor Red
                    } catch {
                        Write-Host "Unexpected error: $($Error[1])" -ForegroundColor Red
                    }
                    $finished = ($consecutiveErrors -gt 9) # If we have 10 errors in a row, we stop processing
                }
            }

            RemoveProcessedItemsFromList $deleteIds $results $SuppressNotFoundErrors $ItemsToDelete

            $percentComplete = ( ($totalItems - $ItemsToDelete.Count) / $totalItems ) * 100
            Write-Progress -Activity $progressActivity -Status "$percentComplete% complete" -PercentComplete $percentComplete

            if ($ItemsToDelete.Count -eq 0) {
                $finished = $True
            }
        }
        Write-Progress -Activity $progressActivity -Status "Complete" -Completed
    }

    function InitLists() {
        $genericItemIdList = [System.Collections.Generic.List``1].MakeGenericType([Microsoft.Exchange.WebServices.Data.ItemId])
        $script:ItemsToDelete = [Activator]::CreateInstance($genericItemIdList)
    }

    function ProcessItem( $item ) {
        # We have found an item, so this function handles any processing
        $script:RequiredPropSet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,
            [Microsoft.Exchange.WebServices.Data.ItemSchema]::Subject,
            [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::Sender,
            [Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass,
            [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::InternetMessageId,
            [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::ReceivedBy,
            [Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated)
        $item.Load($script:RequiredPropSet)

        $itemResult = New-Object PSObject -Property @{ InternetMessageId=$item.InternetMessageId; Sender=$item.Sender; ReceivedBy=$item.ReceivedBy; Id=$item.Id; ItemClass=$item.ItemClass; Subject=$item.Subject; DateTimeCreated=$item.DateTimeCreated; Folder=$folderPath; MailboxType=$Script:MailboxType }
        $itemResult | Export-Csv -Path $ResultsFile -NoTypeInformation -Append
        if ($DeleteContent) {
            #LogVerbose "Adding item to delete list: $($item.Subject)"
            $script:ItemsToDelete.Add($item.Id)
            return # If we are deleting an item, then no other updates are relevant
        }
    }

    function GetFolder() {
        # Return a reference to a folder specified by path

        $RootFolder, $FolderPath, $Create = $args[0]

        if ($null -eq  $RootFolder) {
            #LogVerbose "GetFolder called with null root folder"
            return $null
        }

        if ($FolderPath.ToLower().StartsWith("wellknownfoldername")) {
            # Well known folder, so bind to it directly
            $wkf = $FolderPath.SubString(20)
            #LogVerbose "Attempting to bind to well known folder: $wkf"
            $folderId = New-Object Microsoft.Exchange.WebServices.Data.FolderId([Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::$wkf, $mbx )
            $Folder = ThrottledFolderBind($folderId)
            return $Folder
        }

        $Folder = $RootFolder
        if ($FolderPath -ne '\') {
            $PathElements = $FolderPath -split '\\'
            for ($i=0; $i -lt $PathElements.Count; $i++) {
                if ($PathElements[$i]) {
                    $View = New-Object  Microsoft.Exchange.WebServices.Data.FolderView(2, 0)
                    $View.PropertySet = [Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly

                    $SearchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName, $PathElements[$i])

                    $FolderResults = $Null
                    try {
                        $FolderResults = $Folder.FindFolders($SearchFilter, $View)
                    } catch {
                        Write-Error "Unable to locate folders."
                    }
                    if ($null -eq $FolderResults) {
                        if (Throttled) {
                            try {
                                $FolderResults = $Folder.FindFolders($SearchFilter, $View)
                            } catch {
                                Write-Error "Unable to locate folders."
                            }
                        }
                    }
                    if ($null -eq $FolderResults) {
                        return $null
                    }

                    if ($FolderResults.TotalCount -gt 1) {
                        # We have more than one folder returned... We shouldn't ever get this, as it means we have duplicate folders
                        $Folder = $null
                        Write-Host "Duplicate folders ($($PathElements[$i])) found in path $FolderPath" -ForegroundColor Red
                        break
                    } elseif ( $FolderResults.TotalCount -eq 0 ) {
                        if ($Create) {
                            # Folder not found, so attempt to create it
                            $subfolder = New-Object Microsoft.Exchange.WebServices.Data.Folder($RootFolder.Service)
                            $subfolder.DisplayName = $PathElements[$i]
                            try {
                                $subfolder.Save($Folder.Id)
                                #LogVerbose "Created folder $($PathElements[$i])"
                            } catch {
                                # Failed to create the subfolder
                                $Folder = $null
                                Write-Host "Failed to create folder $($PathElements[$i]) in path $FolderPath" -ForegroundColor Red
                                break
                            }
                            $Folder = $subfolder
                        } else {
                            # Folder doesn't exist
                            $Folder = $null
                            Write-Host "Folder $($PathElements[$i]) doesn't exist in path $FolderPath" -ForegroundColor Red
                            break
                        }
                    } else {
                        $Folder = ThrottledFolderBind $FolderResults.Folders[0].Id $null $RootFolder.Service
                    }
                }
            }
        }

        $Folder
    }

    function SearchMailbox() {
        $Script:ewsService = CreateService($Mailbox)
        if ($null -eq $Script:ewsService) {
            return
        }
        # Set our root folder
        if ($Archive) {
            $Script:MailboxType = "Archive"
            if ($SearchDumpster) {
                $ProcessSubfolders = $True
                $rootFolderId = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::ArchiveRecoverableItemsRoot
            } else {
                $rootFolderId = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::ArchiveMsgFolderRoot
            }
        } else {
            $Script:MailboxType = "Primary"
            if ($SearchDumpster) {
                $ProcessSubfolders = $True
                $rootFolderId = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::RecoverableItemsRoot
            } else {
                $rootFolderId = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::MsgFolderRoot
            }
        }

        #InitPropList

        if (!($IncludeFolderList)) {
            # No folders specified to search, so the entire mailbox will be searched
            $FolderId = New-Object Microsoft.Exchange.WebServices.Data.FolderId( $rootFolderId )
            $ProcessSubfolders = $true
            SearchFolder $FolderId
        } else {
            # Searching specific folders
            $rootFolder = ThrottledFolderBind $rootFolderId
            foreach ($includedFolder in $IncludeFolderList) {
                $folder = $null
                $folder = GetFolder($rootFolder, $includedFolder, $false)

                if ($folder) {
                    $folderPath = GetFolderPath($folder)
                    SearchFolder $folder.Id
                }
            }
        }
    }

    function Throttled() {
        # Checks if we've been throttled.  If we have, we wait for the specified number of BackOffMilliSeconds before returning

        if ([String]::IsNullOrEmpty($script:Tracer.LastResponse)) {
            return $false # Throttling does return a response, if we don't have one, then throttling probably isn't the issue (though sometimes throttling just results in a timeout)
        }

        $lastResponse = $script:Tracer.LastResponse.Replace("<?xml version=`"1.0`" encoding=`"utf-8`"?>", "")
        $lastResponse = "<?xml version=`"1.0`" encoding=`"utf-8`"?>$lastResponse"
        $responseXml = [xml]$lastResponse

        if ($responseXml.Trace.Envelope.Body.Fault.detail.MessageXml.Value.Name -eq "BackOffMilliseconds") {
            # We are throttled, and the server has told us how long to back off for
            Write-Host "Throttling detected, server requested back off for $($responseXml.Trace.Envelope.Body.Fault.detail.MessageXml.Value."#text") milliseconds" Yellow
            Start-Sleep -Milliseconds $responseXml.Trace.Envelope.Body.Fault.detail.MessageXml.Value."#text"
            Write-Host "Throttling budget should now be reset, resuming operations" Gray
            return $true
        }
        return $false
    }

    function ThrottledFolderBind() {
        param (
            [Microsoft.Exchange.WebServices.Data.FolderId]$folderId,
            $propSet = $null,
            $exchangeService = $null)

        $folder = $null
        if ($null -eq $exchangeService) {
            $exchangeService = $Script:ewsService
        }

        try {
            if ($null -eq $propSet) {
                $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchangeService, $folderId)
            } else {
                $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchangeService, $folderId, $propSet)
            }
            if (!($null -eq $folder)) {
                Write-Verbose "Successfully bound to folder $folderId"
            }
            return $folder
        } catch {
            Write-Error "Unable to bind to the $($folderId) folder."
        }

        if (Throttled) {
            try {
                if ($null -eq $propSet) {
                    $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchangeService, $folderId)
                } else {
                    $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($exchangeService, $folderId, $propSet)
                }
                if (!($null -eq $folder)) {
                    Write-Verbose "Successfully bound to folder $folderId"
                }
                return $folder
            } catch {
                Write-Error "Unable to bind to the $($folderId) folder."
            }
        }

        # If we get to this point, we have been unable to bind to the folder
        Write-HostLog"FAILED to bind to folder $folderId"
        return $null
    }

    function GetFolderPath($Folder) {
        # Return the full path for the given folder

        # We cache our folder lookups for this script
        if (!$script:folderCache) {
            # Note that we can't use a PowerShell hash table to build a list of folder Ids, as the hash table is case-insensitive
            # We use a .Net Dictionary object instead
            $script:folderCache = New-Object 'System.Collections.Generic.Dictionary[System.String,System.Object]'
        }

        $propSet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly, [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName, [Microsoft.Exchange.WebServices.Data.FolderSchema]::ParentFolderId)
        $parentFolder = ThrottledFolderBind $Folder.Id $propSet $Folder.Service
        $folderPath = $Folder.DisplayName
        $parentFolderId = $Folder.Id
        while ($parentFolder.ParentFolderId -ne $parentFolderId) {
            if ($script:folderCache.ContainsKey($parentFolder.ParentFolderId.UniqueId)) {
                try {
                    $parentFolder = $script:folderCache[$parentFolder.ParentFolderId.UniqueId]
                } catch {
                    Write-Error "Unable to find the parent folder."
                }
            } else {
                $parentFolder = ThrottledFolderBind $parentFolder.ParentFolderId $propSet $Folder.Service
                $script:FolderCache.Add($parentFolder.Id.UniqueId, $parentFolder)
            }
            $folderPath = $parentFolder.DisplayName + "\" + $folderPath
            $parentFolderId = $parentFolder.Id
        }
        return $folderPath
    }

    function GetWellKnownFolderPath($WellKnownFolder) {
        if (!$script:wellKnownFolderCache) {
            $script:wellKnownFolderCache = @{}
        }

        if ($script:wellKnownFolderCache.ContainsKey($WellKnownFolder)) {
            return $script:wellKnownFolderCache[$WellKnownFolder]
        }

        $folder = $null
        $folderPath = $null
        $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($Script:ewsService, $WellKnownFolder)
        if ($folder) {
            $folderPath = GetFolderPath($folder)
            #LogVerbose "GetWellKnownFolderPath: Path for $($WellKnownFolder): $folderPath"
        }
        $script:wellKnownFolderCache.Add($WellKnownFolder, $folderPath)
        return $folderPath
    }

    function IsFolderExcluded() {
        # Return $true if folder is in the excluded list

        param ($folderPath)

        # To support localization, we need to handle WellKnownFolderName enumeration
        # We do this by putting all our excluded folders into a hash table, and checking that we have the full path for any well known folders (which we retrieve from the mailbox)
        if ($null -eq $script:excludedFolders) {
            # Create and build our hash table
            $script:excludedFolders = @{}

            if ($ExcludeFolderList) {
                #LogVerbose "Building folder exclusion list"#: $($ExcludeFolderList -join ',')"
                foreach ($excludedFolder in $ExcludeFolderList) {
                    $excludedFolder = $excludedFolder.ToLower()
                    $wkfStart = $excludedFolder.IndexOf("wellknownfoldername")
                    #LogVerbose "Excluded folder: $excludedFolder"
                    if ($wkfStart -ge 0) {
                        # Replace the well known folder name with its full path
                        $wkfEnd = $excludedFolder.IndexOf("\", $wkfStart)-1
                        if ($wkfEnd -lt 0) { $wkfEnd = $excludedFolder.Length }
                        $wkf = $null
                        $wkf = $excludedFolder.SubString($wkfStart+20, $wkfEnd - $wkfStart - 19)

                        $wellKnownFolder = [Microsoft.Exchange.WebServices.Data.WellKnownFolderName]::$wkf
                        $wellKnownFolderPath = GetWellKnownFolderPath($wellKnownFolder)

                        $excludedFolder = $excludedFolder.Substring(0, $wkfStart) + $wellKnownFolderPath + $excludedFolder.Substring($wkfEnd+1)
                        #LogVerbose "Path of excluded folder: $excludedFolder"
                    }
                    $script:excludedFolders.Add($excludedFolder, $null)
                }
            }
        }

        return $script:excludedFolders.ContainsKey($folderPath.ToLower())
    }

    function SearchFolder( $FolderId ) {
        # Bind to the folder and show which one we are processing
        $folder = $null
        CheckTokenExpiry -Environment $Environment -Token ([ref]$Script:EWSToken) -EWSService ([ref]$Script:ewsService) -ApplicationInfo $Script:applicationInfo -EWSOnlineURL $Script:ewsOnlineURL -EWSOnlineScope $Script:ewsOnlineScope -AzureADEndpoint $azureADEndpoint
        $folder = [Microsoft.Exchange.WebServices.Data.Folder]::Bind($Script:ewsService, $FolderId)

        if ($null -eq $folder) { return }

        $folderPath = GetFolderPath($folder)

        if (IsFolderExcluded($folderPath)) {
            return
        }

        InitLists

        Write-Host "Searching the $($folderPath) for items." -ForegroundColor Gray

        # Search the folder for any matching items
        $pageSize = 100 # We will get details for up to 100 items at a time
        $moreItems = $true

        # Configure ItemView
        $view = New-Object Microsoft.Exchange.WebServices.Data.ItemView($pageSize, $offset, [Microsoft.Exchange.WebServices.Data.OffsetBasePoint]::Beginning)
        $view.PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly,
            [Microsoft.Exchange.WebServices.Data.ItemSchema]::Subject,
            [Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::Sender)
        $view.Offset = 0
        $view.Traversal = [Microsoft.Exchange.WebServices.Data.ItemTraversal]::Shallow

        # Configure the search filter using the provided criteria
        $filters = @()

        if (![String]::IsNullOrEmpty($MessageClass)) {
            $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.ItemSchema]::ItemClass, $MessageClass)
        }

        if (![String]::IsNullOrEmpty($Subject)) {
            $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.ItemSchema]::Subject, $Subject)
        }

        if (![String]::IsNullOrEmpty($Sender)) {
            $senderEmailAddress = New-Object Microsoft.Exchange.WebServices.Data.EmailAddress($Sender)
            $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::Sender, $senderEmailAddress)
        }

        if (![String]::IsNullOrEmpty($MessageId)) {
            $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsEqualTo([Microsoft.Exchange.WebServices.Data.EmailMessageSchema]::InternetMessageId, $MessageId)
        }

        if (![string]::IsNullOrEmpty($MessageBody)) {
            $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+ContainsSubstring([Microsoft.Exchange.WebServices.Data.ItemSchema]::Body, $MessageBody)
        }

        # Add filter(s) for creation time
        if ( $CreatedAfter ) {
            $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsGreaterThanOrEqualTo([Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated, $CreatedAfter)
        }
        if ( $CreatedBefore ) {
            $filters += New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+IsLessThanOrEqualTo([Microsoft.Exchange.WebServices.Data.ItemSchema]::DateTimeCreated, $CreatedBefore)
        }

        # Create the search filter
        $searchFilter = New-Object Microsoft.Exchange.WebServices.Data.SearchFilter+SearchFilterCollection([Microsoft.Exchange.WebServices.Data.LogicalOperator]::And)
        foreach ($filter in $filters) {
            #LogVerbose([string]::Format("Adding search filter: {0}.", $filter.Value))
            $searchFilter.Add($filter)
        }

        # Perform the search and display the results
        while ($moreItems) {
            CheckTokenExpiry -Environment $Environment -Token ([ref]$Script:EWSToken) -EWSService ([ref]$Script:ewsService) -ApplicationInfo $Script:applicationInfo -EWSOnlineURL $Script:ewsOnlineURL -EWSOnlineScope $Script:ewsOnlineScope -AzureADEndpoint $azureADEndpoint
            $results = $Script:ewsService.FindItems( $FolderId, $searchFilter, $view )
            if ($results.Count -gt 0) {
                foreach ($item in $results.Items) {
                    ProcessItem $item
                }
            }

            $moreItems = $results.MoreAvailable
            $view.Offset += $pageSize
        }

        if ($script:ItemsToDelete.Count -gt 0) {
            # Delete the items we found in this folder
            ThrottledBatchDelete $script:ItemsToDelete -SuppressNotFoundErrors $true
        }

        # Now search subfolders
        if ($ProcessSubfolders) {
            $view = New-Object Microsoft.Exchange.WebServices.Data.FolderView(500)
            $view.PropertySet = New-Object Microsoft.Exchange.WebServices.Data.PropertySet([Microsoft.Exchange.WebServices.Data.BasePropertySet]::IdOnly, [Microsoft.Exchange.WebServices.Data.FolderSchema]::DisplayName)
            foreach ($subFolder in $folder.FindFolders($view)) {
                SearchFolder $subFolder.Id $folderPath
            }
        }
    }
}
process {}
end {
    # The following is the main script
    $Date = [DateTime]::Now
    $Script:StartTime = '{0:MM/dd/yyyy HH:mm:ss}' -f $Date
    $ResultsFile = "$OutputPath\$Mailbox-SearchResults-$('{0:MMddyyyyHHmms}' -f $Date).csv"

    # Load EWS Managed API
    if (!(LoadEWSManagedAPI)) {
        Write-Host "Failed to locate EWS Managed API, cannot continue" -ForegroundColor Red
        exit
    }

    $script:searchResults = @()

    # Process as single mailbox
    $loggerParams = @{
        LogDirectory             = $OutputPath
        LogName                  = "EwsSearchAndDelete-$((Get-Date).ToString("yyyyMMddhhmmss"))-Debug"
        AppendDateTimeToFileName = $false
        ErrorAction              = "SilentlyContinue"
    }

    $Script:Logger = Get-NewLoggerInstance @loggerParams

    SetWriteHostAction ${Function:Write-HostLog}
    SetWriteVerboseAction ${Function:Write-VerboseLog}
    SetWriteWarningAction ${Function:Write-HostLog}

    $cloudService = Get-CloudServiceEndpoint $AzureEnvironment

    # Define the endpoints that we need for the various calls to the Azure AD Graph API and EWS
    $Script:ewsOnlineURL = "$($cloudService.ExchangeOnlineEndpoint)/EWS/Exchange.asmx"
    $Script:ewsOnlineScope = "$($cloudService.ExchangeOnlineEndpoint)/.default"
    $autoDSecureName = $cloudService.AutoDiscoverSecureName
    $azureADEndpoint = $cloudService.AzureADEndpoint

    # Perform the search
    SearchMailbox
}
