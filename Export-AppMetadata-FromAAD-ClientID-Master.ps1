#referenced https://gallery.technet.microsoft.com/Azure-AD-Integrated-44658ec2
#The script requires a connection to Azure AD with an account which has permissions to read service principal objects, OAuth permission objects, App role assignments, etc.
#It also uses a clientID/secret to connect to MS Graph and get per application login information
#Beware that for non-premium tenants AAD only stores 7 days of login information. Premium tenants have 30 days of login data available.
#It is recommended to use certficate for authentication, instead of clientid/secret


if (!(Get-Module AzureAD -ListAvailable | ? {($_.Version.Major -gt 1 -and $_.Version.Build -gt 1 -and $_.Version.Revision -gt 3) -or ($_.Version.Major -eq 2 -and $_.Version.Build -eq 2)})) { Write-Host -BackgroundColor Red "This script requires a recent version of the AzureAD PowerShell module. Download it here: https://www.powershellgallery.com/packages/AzureAD/"; return} 

try {Get-AzureADTenantDetail | Out-Null} 
catch { Connect-AzureAD | Out-Null } 


Write-Host "==============================================================="
Write-Host "Gathering information about Azure AD integrated applications..." -ForegroundColor Yellow 
Write-Host "==============================================================="

#Get a list of Azure AD Integrated Apps - Excludes 1st party apps like Office 365 and other similar Microsoft services 
try {$ServicePrincipals = Get-AzureADServicePrincipal -All:$true | ? {$_.Tags -eq "WindowsAzureActiveDirectoryIntegratedApp"} } 
catch {Write-Host "You must connect to Azure AD first!" -ForegroundColor Red -ErrorAction Stop } 

#Declare App Permissions Array
$appPermissions = @();$i=0;

# Change these three values to your application and tenant settings
$clientID = "xxxxxxxxxxxxxxx" # CLIENT ID for application
$clientSecret = "xxxxxxxxxxxxxxxx" # KEY for application
$tenantdomain = "xxxxxxxxxxxxxxxx" # The tenant domain name

# Static values
$resAzureGraphAPI = "https://graph.microsoft.com";
#$serviceRootURL = "https://graph.microsoft.com" #/$tenant"
$authString = "https://login.microsoftonline.com/$tenantdomain"

$Global:AzureToken = $null

# Creates a context for login.microsoftonline.com (Azure AD common authentication)
$AuthContext = [Microsoft.IdentityModel.Clients.ActiveDirectory.AuthenticationContext]$authString

# Creates a credential from the client id and key
$clientCredential = New-Object -TypeName "Microsoft.IdentityModel.Clients.ActiveDirectory.ClientCredential"($clientID, $clientSecret)


Function Get-AzureToken
{
    Try
    {
        $graphquery="https://graph.microsoft.com/beta/auditLogs/signIns?&filter=appId eq '$appid'&top=1"

        $auditlogs = Invoke-RestMethod -Method GET -Uri $graphquery -Headers @{Authorization=$AzureToken.CreateAuthorizationHeader()} -ContentType "application/json"
    }
    Catch{
        If (($Error[0].Exception.Message -like "*: (401) Unauthorized*") -or ($Error[0].Exception.Message -like "*You cannot call a method on a null-valued expression*"))
        {

           
            Write-Host "Refreshing token due to: $($Error[0].Exception.Message)"
            Write-Host -ForegroundColor Yellow "Refreshing Access Token..."

            # Requests a bearer token
            $authenticationTask = $AuthContext.AcquireTokenAsync($resAzureGraphAPI, $clientCredential);
            $authenticationTask.Wait()

            $Global:AzureToken = $authenticationTask.Result
            $Error=$null
        }
    }

}

Get-AzureToken

Function GetSignininfo ($appid)
{

    $auditlogs=$null 
    $result = $false

    Try
    {
        $graphquery="https://graph.microsoft.com/beta/auditLogs/signIns?&filter=appId eq '$appid'&top=1"

        $auditlogs = Invoke-RestMethod -Method GET -Uri $graphquery -Headers @{Authorization=$AzureToken.CreateAuthorizationHeader()} -ContentType "application/json"
    }
    Catch{
        If (($Error[0].Exception.Message -like "*: (401) Unauthorized*") -or ($Error[0].Exception.Message -like "*You cannot call a method on a null-valued expression*"))
        {

           Get-AzureToken
           $graphquery="https://graph.microsoft.com/beta/auditLogs/signIns?&filter=appId eq '$appid'&top=1"

           $auditlogs = Invoke-RestMethod -Method GET -Uri $graphquery -Headers @{Authorization=$AzureToken.CreateAuthorizationHeader()} -ContentType "application/json"
           $Error = $null
        }
    }
         

    if ($auditlogs.value -ne $null) 
    {
        $result = $true
    } 
   

    Return $result
}


      
$appcount= $ServicePrincipals.count
Write-Host "Found $appcount Applications to Process:" -ForegroundColor green 
Write-Host "==============================================================="
 
foreach ($ServicePrincipal in $ServicePrincipals) { 
    $i++

    Write-Host "[$i of $appcount] Processing: $($ServicePrincipal.DisplayName)"  -ForegroundColor Green 
    #Declare new empty object to store metadata for each service principal
    $objPermissions = New-Object PSObject 
    
    #Declare signin variable
    $signin=$null
    
    #Has application been given delegated admin consent  
    $adminConsent = "N/A"

    #Has application been given admin application permissions
    $adminAppPermissions = "N/A"

    #Declare empty array to store the resources which the SP has been delegated permissions to on behalf of a user
    $OAuthAdminresname = @();$OAuthUserresname = @();

    #Declare Application Type
    $apptype=$null
    
    #Declare other variables
    $assignedto = @();$resID = $null; $userId = $null;    

    $OAuthcount=0;$RolesUserCount=0;$RolesGroupCount=0;$RolesAppCount=0;$ConsentedUserCount=0

    #Placeholder for replyURLs collection
    $replyURLs = $null
    
    $tag = $null
    $tags = $null
    $SPperm=$null
    $RolesAppResNames=$null

     
    #Only lists delegated "constented" permissions. 
    #Every consent is tracked in an object - OAuth2permissiongrant.
    #To get all OAuth2permissiongrants for a specific SP run the command below
    #The clientID property of a consent grant is the SP object ID for the respective application, which is granted some rights over some resource:resourceID

    $SPperm = Get-AzureADServicePrincipalOAuth2PermissionGrant -ObjectId $ServicePrincipal.ObjectId -All:$true 

    if ($SPperm) 
    {
        $ConsentedUserCount = @($SPperm | ? {$_.ConsentType -eq "Principal"} | select PrincipalId -Unique).count
        
        $adminConsent=$false
    }
    
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Users Consented" -Value $ConsentedUserCount
            

    #Get application permissions (type=AppRoleAssignment) assigned to SPN by an admin. This subject is a user or group, which may be assigned permissions to use a SAML/AAD Proxy application
    #In Azure AD Portal look at users and groups blade under application
    $SPRoles = Get-AzureADServiceAppRoleAssignment -ObjectId $ServicePrincipal.ObjectId -All:$true | Select PrincipalType, PrincipalId, ResourceDisplayName


    
    if ($SPRoles) 
    {

        #Must use an array to get 0 or 1 as a number, else the array is collapsed and nothing is returned
        #supported principaltypes are user,group, and application (look for PrincipalType=ServicePrincipal)
        #User/group assignments can be seen from enterprise applications
        #App assignments can be seen from permissions type=application. Application A is assigned certain permissions against API/App B

        $RolesUserCount = @($SPRoles | ? {$_.PrincipalType -eq "User"} | select PrincipalId -Unique).count
        $RolesGroupCount = @($SPRoles | ? {$_.PrincipalType -eq "Group"} | select PrincipalId -Unique).count
        $RolesAppCount = @($SPRoles | ? {$_.PrincipalType -eq "ServicePrincipal"} | select ResourceId -Unique).count
        
        
    }

    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Roles - User Count" -Value $RolesUserCount
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Roles - Group Count" -Value $RolesGroupCount
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Roles - App Count" -Value $RolesAppCount
   
    
    #Get application permissions (type=AppRoleAssignment) assigned to SPN by an admin. This subject here is the application, which may be assigned permissions to use MS Graph
    #These are application permissions assigned to the app and consented by an admin
    
    $SPAppRoles = Get-AzureADServiceAppRoleAssignedTo -ObjectId $ServicePrincipal.ObjectId -All:$true 

    if ($SPAppRoles)
    {   
       $adminAppPermissions = $true

       $RolesAppResNames = ($SPAppRoles | ? {$_.PrincipalType -eq "ServicePrincipal"} | select ResourceDisplayName -Unique).ResourceDisplayName -join ";"

       
    }

     Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "App Permissions Assigned To" -Value $RolesAppResNames
    
      #Set Application Type 

    if ($ServicePrincipal.Tags.Contains("WindowsAzureActiveDirectoryOnPremApp")) 
    {
        $apptype="AAD App Proxy"
    }
    elseif($ServicePrincipal.Tags.Contains("WindowsAzureActiveDirectoryGalleryApplicationPrimaryV1"))
    {
        $apptype="AAD App Gallery"
    }
    elseif($ServicePrincipal.Tags.Contains("WindowsAzureActiveDirectoryGalleryApplicationNonPrimaryV1"))
    {
        if($ServicePrincipal.Tags.Contains("WindowsAzureActiveDirectoryCustomSingleSignOnApplication"))
        {
            $apptype="AAD App 3d Party + SSO"
        }
        else
        {
            $apptype="AAD App 3d Party"
        }
    }
    
 
    
    foreach ($replyurl in $ServicePrincipal.ReplyUrls) {$replyURLs+= "[" + $replyurl+ "]"}

    foreach ($tag in $ServicePrincipal.tags) {$tags+=  "[" + $tag + "]"}

    if ($replyURLs)
    {
        if ($replyURLs.ToUpper().Contains("SAML"))
        {
            $apptype=$apptype + " SAML"
        }
    }
    
    
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Application Name" -Value $ServicePrincipal.DisplayName 
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "ApplicationId" -Value $ServicePrincipal.AppId 

    #If AAD tenant name was renamed it may show up with the old name(s) and new name on the app report
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Publisher" -Value $ServicePrincipal.PublisherName 
    
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Homepage" -Value $ServicePrincipal.Homepage 
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "ReplyURLs" -Value $replyURLs
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Tags" -Value $tags
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Service Principal ObjectId" -Value $ServicePrincipal.ObjectId 
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Enabled" -Value $ServicePrincipal.AccountEnabled 
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "AssignmentRequired" -Value $ServicePrincipal.AppRoleAssignmentRequired
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "App Permissions Assigned" -Value $adminAppPermissions

    $signin=GetSignininfo($ServicePrincipal.appid)
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Signed Last 30 Days" -Value $signin

    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Longest Consent Valid Until" -Value ($SPperm.ExpiryTime | select -Unique | sort -Descending | select -First 1) 
     
    $SPperm | % {
        #Foreach delegated oAuth permission 

        #Get Resource Name (will equal some API)
        $resID = (Get-AzureADObjectByObjectId -ObjectIds $_.ResourceId).DisplayName 
        
        #If there is a principalid, it means inidividual user consent, else it is an admin consent.
        if ($_.PrincipalId) 
        { 
            $OAuthUserresname+=(Get-AzureADObjectByObjectId -ObjectIds $_.ResourceId).DisplayName 
        } 
        else
        {
            $OAuthAdminresname+=(Get-AzureADObjectByObjectId -ObjectIds $_.ResourceId).DisplayName 
        }
    
    } 

    
    #concatenate/join all keys and values in a OAuthpermission table and store in objPermissions property
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Admin Consented To" -Value (($OAuthAdminresname | Select -Unique)  -join ";") 
     
    #concatenate/join all keys and values in a OAuthpermission table and store in objPermissions property
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Users Consented To" -Value (($OAuthUserresname | Select -Unique)  -join ";") 
       
    #if any the consent type is Allprincipals set admin consent to true
    if (($SPperm.ConsentType | select -Unique) -eq "AllPrincipals") {$adminConsent = $true} 

    #Mark as OIDC/OAuth2.0 app if apptpe is null and the app service principal is in OAuth consent grants. 
    if (($SPperm.ConsentType) -and ($apptype -eq $null)){$apptype="OIDC/oAuth2.0"}


    if (!$apptype)
    {
         if ($ServicePrincipal.Tags.Contains("WindowsAzureActiveDirectoryIntegratedApp")) 
         {
            #If after all checks, apptype is null check for AADIntegratedApp, if present set to AAD Integrated
            $apptype="AAD Integrated"

         }
         else
         {
             $apptype="Unknown"
         }
    }
    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "App Type" -Value $apptype 

    Add-Member -InputObject $objPermissions -MemberType NoteProperty -Name "Admin Consent" -Value $adminConsent
    
    
     
    $appPermissions += $objPermissions 
} 
 
$appPermissions | select 'Application name', 'Publisher', 'App Type', 'Enabled', 'Signed Last 30 Days','Roles - User Count','Roles - Group Count', 'Roles - App Count', 'Admin Consent', 'Admin Consented To','Users Consented', 'Users Consented To', 'App Permissions Assigned', 'App Permissions Assigned To','Longest Consent Valid Until', 'ApplicationId', 'Service Principal ObjectId','Homepage', 'ReplyURLs','Tags' | Export-CSV -nti -Path "$((Get-Date).ToString('yyyy-MM-dd_HH-mm-ss'))_AppInventory.csv"
 
Write-Host "==============================================================" 
Write-Host "See current directory for an *********appinventory.csv report." -ForegroundColor Yellow
Write-Host "==============================================================" 


#write a separate script to just export all the user and group assignments and all the OAuth2 assignments.