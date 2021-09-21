using System.Collections.Generic;
using Newtonsoft.Json;
using Topshelf;
using Topshelf.Logging;

using OneIdentity.ARSGJitAccess.Common;
using OneIdentity.SafeguardDotNet.Event;
using System;
using System.Collections.ObjectModel;

// TODO check right location to add reference: C:\Windows\assembly\GAC_MSIL\System.Management.Automation\1.0.0.0__31bf3856ad364e35
// Also, can get it by executing for example 'Copy [PSObject].Assembly.Location C:\temp'
using System.Management.Automation;
using System.Management.Automation.Runspaces;

namespace OneIdentity.ARSGJitAccess.Service
{
    partial class Service : ServiceControl
    {
        public Service(bool isTest)
        {
            Log = HostLogger.Get(typeof(HostFactory));
            IsTest = isTest;            
        }

        public static List<SafeguardEvent> Events
        {
            get
            {
                return new List<SafeguardEvent>()
                {
                    new SafeguardEvent() { name = "AccessRequestAvailable"},
                    new SafeguardEvent() { name = "AccessRequestCancelled"},
                    new SafeguardEvent() { name = "AccessRequestCheckedIn"},
                    new SafeguardEvent() { name = "AccessRequestClosed"},
                    new SafeguardEvent() { name = "AccessRequestExpired"},
                    new SafeguardEvent() { name = "AccessRequestRevoked"},
                };
            }
        }
        public bool IsTest { get; }

        public bool Start(HostControl hostControl)
        {
            // Posh
            Log.Info("JIT Service Start");
            Log.Info("Using ARSActive: " + Config.ARSActive);
            Log.Info("Using PoshActive: " + Config.PoshActive);
            Log.Info("Using PoshScript: " + Config.PoshScript + ", " + Config.PoshWorkingDir);

            if (Config.ARSActive != null && Boolean.Parse(Config.ARSActive))
            {
                if (ActiveRolesClient == null)
                {
                    if (!InitActiveRolesClient())
                    {
                        Log.Fatal("Failed to create ActiveRolesClient");
                        return false;
                    }
                }
            }
            else
            {
                Log.Fatal("Not initalizing ActiveRolesClient");
            }

            if (SafeguardClient == null)
            {
                if (!InitSafeguardClient())
                {
                    Log.Fatal("Failed to create SafeguardClient");
                    return false;
                }
            }

            if (IsTest)
            { 
                Log.Info("Test mode enabled.  Stopping service before listening.");
                hostControl.Stop();
                return true;
            }

            // Start listener
            try
            {
                if (Listener == null)
                {
                    Listener = SafeguardClient.GetEventListener();
                }
                foreach (var e in Events)
                {
                    Listener.RegisterEventHandler(e.name, HandleAccessRequestEvent);
                }
                Listener.Start();

                Log.Info("Service Started");
                return true;
            }
            catch(Exception e)
            {
                Log.Fatal(e.Message);
            }

            return false;
        }

        public bool Stop(HostControl hostControl)
        {
            if (IsTest)
            {
                return true;
            }

            if (Listener != null)
            {
                Listener.Stop();
                Log.Info("Service Stopped");
            }

            return true;
        }

        void HandleAccessRequestEvent(string eventName, string eventBody)
        {
            var accessRequestEvent = JsonConvert.DeserializeObject<AccessRequestEvent>(eventBody);
            
            Log.Debug($"Recieved event: {eventName}, AssetId: {accessRequestEvent.AssetId}, AccountId: {accessRequestEvent.AccountId}");
            
            var assetAccount = SafeguardClient.GetAssetAccount(accessRequestEvent.AccountId);

            Log.Info($"assetAccount domain name: {assetAccount.DomainName}  assetAccount PlatformType: {assetAccount.PlatformType} assetAccount DN: {assetAccount.DistinguishedName}");

            if (Boolean.Parse(Config.ARSActive))
            {
                Log.Info($"ARS sending event to ARS");
                if (assetAccount.PlatformType == "MicrosoftAD")
                {
                    if (eventName == "AccessRequestAvailable")
                    {
                        ActiveRolesClient.SetObjectAttribute(assetAccount.DistinguishedName, Config.ARSGJitAccessAttribute, "true");
                        Log.Info($"Grant access for: {assetAccount.DistinguishedName}. Set {Config.ARSGJitAccessAttribute} = true.");
                    }
                    else
                    {
                        ActiveRolesClient.SetObjectAttribute(assetAccount.DistinguishedName, Config.ARSGJitAccessAttribute, "false");
                        Log.Info($"Revoke access for: {assetAccount.DistinguishedName}. Set {Config.ARSGJitAccessAttribute} = false.");
                    }
                }
                else
                {
                    Log.Debug($"Ignored event for {assetAccount.Name}, because PlatformType is: {assetAccount.PlatformType}");
                }
            }
            else
            {
                Log.Info($"ARS not sending event to ARS");
            }

            // Let's go POSH!
            if (Config.PoshActive != null && Boolean.Parse(Config.PoshActive))
            {
                Log.Info($"Configured JIT Posh Script:" + Config.PoshActive + Config.PoshScript + " " + Config.PoshWorkingDir);

                RunPoshScript(Config.PoshWorkingDir, Config.PoshScript, Config.PoshADSAttribute, assetAccount, eventName, eventBody);
            }
            else
            {
                Log.Info($"Not calling Posh script: PoshActive = \"false\" ");
            }
        }

        // Run some Posh...if activated
        private Collection<String> RunPoshScript(string dir, string script, string adsAttribute, SafeguardAssetAccount assetAccount, string eventName, string eventBody)
        {
            // string myScript = "(get-Acl).getType().toString()";
            JITAccessEvent accessRequestAvailable;
            string accountName = null;
            string requestType = null;
            string requesterUsername = null;
            SafeguardUser sgRequesterUser = null;

            try
            {
                Log.Info("Deserializing AccessEvent");
                accessRequestAvailable = JsonConvert.DeserializeObject<JITAccessEvent>(eventBody);
                Log.Info($"AccessEventAvailable accountname: {accessRequestAvailable.AccountName} requestType {accessRequestAvailable.AccessRequestType}");
                accountName = accessRequestAvailable.AccountName;
                requestType = accessRequestAvailable.AccessRequestType;
                requesterUsername = accessRequestAvailable.RequesterUsername;

                sgRequesterUser = SafeguardClient.GetSGUser(accessRequestAvailable.RequesterId.ToString());

            }
            catch (Exception ex)
            {
                Log.Info("Deserializing AccessEventAvailable Exception:" + ex.Message);
            }

            Runspace runspace = RunspaceFactory.CreateRunspace();
            runspace.Open();

            string setExecutionPolicyCmd = "Set-ExecutionPolicy -Force -ExecutionPolicy Unrestricted";
            //string importCmd = @"Import-Module -Force -Verbose " + dir;

            Pipeline pipeline = runspace.CreatePipeline();

            pipeline.Commands.AddScript(String.Format("{0} {1}", "Set-Location", dir));
            pipeline.Commands.AddScript(setExecutionPolicyCmd);
            //pipeline.Commands.AddScript(importCmd);
            // Invoke indicted script passing the key parameters for the event
            pipeline.Commands.AddScript(script +
                " -RequestType '" + requestType +
                "' -RequesterUsername '" + requesterUsername +
                "' -RequesterDN '" + sgRequesterUser.DirectoryProperties.DistinguishedName +
                "' -AccountName '" + accountName +
                "' -EventName '" + eventName +
                "' -PlatFormType '" + assetAccount.PlatformType +
                "' -DomainName '" + assetAccount.DomainName +
                "' -DN '" + assetAccount.DistinguishedName +
                "' -AdsAttribute '" + adsAttribute + "'"
                );

            foreach (Command l in pipeline.Commands)
            {

                Log.Info("COmmand: " + l.CommandText);

            }

            Log.Info("Executing Posh");

            Collection<PSObject> retPSList = pipeline.Invoke();

            // Process the results
            Collection<String> retList = new Collection<string>();
            foreach (var psobject in retPSList)
            {
                String tmpStr = psobject.BaseObject.ToString();
                retList.Add(tmpStr);
                Log.Info("ret value is:" + tmpStr);
            }

            // Cleanup
            runspace.Close();
            pipeline.Dispose();

            return retList;
        } // run posh

        LogWriter Log { get; }
        IActiveRolesClient ActiveRolesClient { get; set; }
        ISafeguardClient SafeguardClient { get; set; }
        ISafeguardEventListener Listener { get; set; }


    }

    class AccessRequestEvent
    {
        public string EventName { get; set; }
        public string AccountId { get; set; }
        public string AssetId { get; set; }
    }



    // TODO is this the right way to code up the event?

    // Root myDeserializedClass = JsonConvert.DeserializeObject<Root>(myJsonResponse); 
    class JITAccessEvent
    {
        public string AccessRequestType { get; set; }
        public object AccountDistinguishedName { get; set; }
        public object AccountDomainName { get; set; }
        public int AccountId { get; set; }
        public string AccountName { get; set; }
        public List<int> ActionUserIds { get; set; }
        public string ApproverAccessRequestUri { get; set; }
        public int AssetId { get; set; }
        public string AssetName { get; set; }
        public string AssetNetworkAddress { get; set; }
        public string AssetPlatformType { get; set; }
        public object Comment { get; set; }
        public int DurationInMinutes { get; set; }
        public bool OfflineWorkflowMode { get; set; }
        public object Reason { get; set; }
        public string ReasonCode { get; set; }
        public string Requester { get; set; }
        public string RequesterAccessRequestUri { get; set; }
        public int RequesterId { get; set; }
        public string RequesterUsername { get; set; }
        public string RequestId { get; set; }
        public DateTime RequiredDate { get; set; }
        public string ReviewerAccessRequestUri { get; set; }
        public object SessionSpsNodeIpAddress { get; set; }
        public object TicketNumber { get; set; }
        public bool WasCheckedOut { get; set; }
        public string EventName { get; set; }
        public string EventDisplayName { get; set; }
        public string EventDescription { get; set; }
        public DateTime EventTimestamp { get; set; }
        public string ApplianceId { get; set; }
        public int EventUserId { get; set; }
        public string EventUserDisplayName { get; set; }
        public string EventUserDomainName { get; set; }
    }
}
