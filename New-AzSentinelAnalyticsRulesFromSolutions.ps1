#requires -version 6.2
<#
    .SYNOPSIS
        This command will read all the Analytic rule templates that have been added from solutions and will
        create new Analytic rules from them.  It will not check to see if a rule has been created from the
        template already.
    .DESCRIPTION
        This command will read all the Analytic rule templates that have been added from solutions and will
        create new Analytic rules from them.  It will not check to see if a rule has been created from the
        template already
    .PARAMETER WorkSpaceName
        Enter the Log Analytics workspace name, this is a required parameter
    .PARAMETER ResourceGroupName
        Enter the Log Analytics workspace name, this is a required parameter

    .NOTES
        AUTHOR: Gary Bushey
        LASTEDIT: 7 Jan 2023
    .EXAMPLE
        New-AzSentinelAnalyticsRulesFromSolutions -WorkspaceName "workspacename" -ResourceGroupName "rgname"
        In this example you will create new rules from all the rule templates that have been created from solutions

   
#>

[CmdletBinding()]
param (
    #[Parameter(Mandatory = $true)]
    [string]$WorkSpaceName = "gabazuresentinel",

    #[Parameter(Mandatory = $true)]
    [string]$ResourceGroupName = "azuresentinel",
    
    [Parameter(Mandatory = $false)][string[]]$SeveritiesToInclude = @("Informational","Low","Medium","High")
)

Function New-AzSentinelAnalyticsRulesFromSolutions ($workspaceName, $resourceGroupName, $filename) {
    #Set up the authentication header
    $context = Get-AzContext
    $azureProfile = [Microsoft.Azure.Commands.Common.Authentication.Abstractions.AzureRmProfileProvider]::Instance.Profile
    $profileClient = New-Object -TypeName Microsoft.Azure.Commands.ResourceManager.Common.RMProfileClient -ArgumentList ($azureProfile)
    $token = $profileClient.AcquireAccessToken($context.Subscription.TenantId)
    $authHeader = @{
        'Content-Type'  = 'application/json' 
        'Authorization' = 'Bearer ' + $token.AccessToken 
    }
    
    $SubscriptionId = $context.Subscription.Id

    #Load all the rule templates so we can copy the information as needed.
    $solutionURL = "https://management.azure.com/providers/Microsoft.ResourceGraph/resources?api-version=2021-03-01"
  
    $query = @"
    Resources 
    | where type =~ 'Microsoft.Resources/templateSpecs/versions' 
    | where tags['hidden-sentinelContentType'] =~ 'AnalyticsRule' 
    and tags['hidden-sentinelWorkspaceId'] =~ '/subscriptions/$($subscriptionId)/resourceGroups/$($ResourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($WorkspaceName)' 
    | extend version = name 
    | extend parsed_version = parse_version(version) 
    | extend resources = parse_json(parse_json(parse_json(properties).template).resources) 
    | extend metadata = parse_json(resources[array_length(resources)-1].properties)
    | extend contentId=tostring(metadata.contentId) 
    | summarize arg_max(parsed_version, version, properties) by contentId 
    | project contentId, version, properties
"@

    $body = @{
        "subscriptions" = @($SubscriptionId)
        "query"         = $query
    }


    $results = Invoke-RestMethod -Uri $solutionURL -Method POST -Headers $authHeader -Body ($body | ConvertTo-Json -EnumsAsStrings -Depth 5)

    
    #Iterate through all the lines in the file
    foreach ($result in $results.data) {
        $template = $result.properties.template.resources.properties
        $kind = $result.properties.template.resources.kind
        $name = $result.contentId
        $displayName = $template.displayName[0]
        $body = ""

        #For some reason there is a null as the last entry in the tactics array so we need to remove it
        $tactics = ""
        # If there is only 1 entry and the null, then if we return just the entry, it gets returned
        # as a string so we need to make sure we return an array
        if ($template.tactics.Count -eq 2) {
            [String[]]$tactics = $template.tactics[0]
        }
        else {
            #Return only those entries that are not null
            $tactics = $template.tactics | Where-Object { $_ -ne $null }
        }

        #For some reason there is a null as the last entry in the techniques array so we need to remove it
        $techniques = ""
        # If there is only 1 entry and the null, then if we return just the entry, it gets returned
        # as a string so we need to make sure we return an array
        if ($template.techniques.Count -eq 2) {
            [String[]]$techniques = $template.techniques[0]
        }
        else {
            #Return only those entries that are not null
            $techniques = $template.techniques | Where-Object { $_ -ne $null }
        }

        #For some reason there is a null as the last entry in the entities array so we need to remove it as well
        #as any entry that is just ".nan"
        $entityMappings = $template.entityMappings  | Where-Object { $_ -ne $null } | Where-Object { $_ -ne ".nan" }
        #If the arrary of EntityMappings only contained one entry, it will not be returned as an arry
        # so we need to convert it into JSON while forcing it to be an array and then convert it back
        # without enumerating the output so that it remains an array
        if ($null -ne $entityMappings) {
            if ($entityMappings.GetType().BaseType.Name -ne "Array") {
                $entityMappings = $entityMappings | ConvertTo-Json -Depth 5 -AsArray | ConvertFrom-Json -NoEnumerate
            }
        }
        #Some entity mappings are stored as empty strings (not sure why) so we need 
        #to check for that and set to null if it is empty so no error gets thrown
        if ([String]::IsNullOrWhiteSpace($entityMappings)) {
            $entityMappings = $null
        }

        #Depending on the type of alert we are creating, the body has different parameters
        switch ($kind) {
            #Not sure if this will ever be used
            "MicrosoftSecurityIncidentCreation" {  
                $body = @{
                    "kind"       = "MicrosoftSecurityIncidentCreation"
                    "properties" = @{
                        "enabled"       = "true"
                        "productFilter" = $template.productFilter
                        "displayName"   = $template.displayName
                    }
                }
            }
            "NRT" {
                #For some reason, all the string values are returned as arrays (with null as the second entry)
                #and we only care about the first entry hence the [0] after everything
                $body = @{
                    "kind"       = "NRT"
                    "properties" = @{
                        "enabled"               = "true"
                        "alertRuleTemplateName" = $name
                        "displayName"           = $template.displayName[0]
                        "description"           = $template.description[0]
                        "severity"              = $template.severity[0]
                        "tactics"               = $tactics
                        "techniques"            = $techniques
                        "query"                 = $template.query[0]
                        "suppressionDuration"   = $template.suppressionDuration[0]
                        "suppressionEnabled"    = $template.suppressionEnabled[0]
                        "eventGroupingSettings" = $template.eventGroupingSettings[0]
                        "templateVersion"       = $template.version[0]
                        "entityMappings"        = $entityMappings
                    }
                }
            }
            "Scheduled" {
                #For some reason, all the string values are returned as arrays (with null as the second entry)
                #and we only care about the first entry hence the [0] after everything
                $body = @{
                    "kind"       = "Scheduled"
                    "properties" = @{
                        "enabled"               = "true"
                        "alertRuleTemplateName" = $name
                        "displayName"           = $template.displayName[0]
                        "description"           = $template.description[0]
                        "severity"              = $template.severity[0]
                        "tactics"               = $tactics
                        "techniques"            = $techniques
                        "query"                 = $template.query[0]
                        "queryFrequency"        = $template.queryFrequency[0]
                        "queryPeriod"           = $template.queryPeriod[0]
                        "triggerOperator"       = $template.triggerOperator[0]
                        "triggerThreshold"      = $template.triggerThreshold[0]
                        "suppressionDuration"   = $template.suppressionDuration[0]
                        "suppressionEnabled"    = $false
                        "eventGroupingSettings" = $template.eventGroupingSettings[0]
                        "templateVersion"       = $template.version[0]
                        "entityMappings"        = $entityMappings
                    }
                }
            }
            Default { }
        }
        #If we have created the body...
        if ("" -ne $body) {
            #Create the GUId for the alert and create it.
            $guid = (New-Guid).Guid
            #Create the URI we need to create the alert.
            $uri = "https://management.azure.com/subscriptions/$($subscriptionId)/resourceGroups/$($resourceGroupName)/providers/Microsoft.OperationalInsights/workspaces/$($workspaceName)/providers/Microsoft.SecurityInsights/alertRules/$($guid)?api-version=2022-12-01-preview"
            try {
                Write-Host "Attempting to create rule $($displayName)"
                $verdict = Invoke-RestMethod -Uri $uri -Method Put -Headers $authHeader -Body ($body | ConvertTo-Json -EnumsAsStrings -Depth 5)
                Write-Output "Succeeded"
            }
            catch {
                #The most likely error is that there is a missing dataset. There is a new
                #addition to the REST API to check for the existance of a dataset but
                #it only checks certain ones.  Hope to modify this to do the check
                #before trying to create the alert.
                $errorReturn = $_
                Write-Error $errorReturn
            }
            #This pauses for 5 second so that we don't overload the workspace.
            Start-Sleep -Seconds 5
        }
    }
}
New-AzSentinelAnalyticsRulesFromSolutions $WorkSpaceName $ResourceGroupName 

