﻿using Serilog;
using System;
using System.Reflection;
using System.Security;
using Topshelf;
using Topshelf.StartParameters;

namespace OneIdentity.ARSGJitAccess.Service
{
    public class Program
    {
        
        public static readonly string AppName = "ARSGJitAccess";
        public static readonly string AppDisplayName = "Active Roles/Safeguard Just-in-time Access";
        public static readonly string AppDescription = "Listens for Safeguard access requests and call Active Roles to set permission granting attribute";
        
        public static void Main()
        {
            bool isTest = false;

            try
            {
                Console.WriteLine("Starting..." + Config.LogLevel);
                // TODO Is this approach of setting loglevel good TopShelf practice?
                if (String.IsNullOrEmpty(Config.LogLevel) ||
                        Config.LogLevel.Equals("Information", StringComparison.InvariantCultureIgnoreCase))
                {

                    Log.Logger = new LoggerConfiguration()
                        .WriteTo.Console()
                        .WriteTo.EventLog(AppName, manageEventSource: true)
                        .MinimumLevel.Information()
                        .CreateLogger();
                }
                else // anything not empty or Information...go debug
                {
                    Log.Logger = new LoggerConfiguration()
                    .WriteTo.Console()
                    .WriteTo.EventLog(AppName, manageEventSource: true)
                    .MinimumLevel.Debug()
                    .CreateLogger();
                }
            }
            catch(SecurityException)
            {
                Log.Logger = new LoggerConfiguration()
                    .WriteTo.Console()
                    .CreateLogger();
                Log.Warning("Unable to access Windows Event Log.  Logging console only");
            }

            var rc = HostFactory.Run(x => 
            {
                Type t = typeof(Program);
                Assembly assembly = t.Assembly;

                x.Service<Service>(hostSettings => new Service(isTest));
                x.RunAsLocalSystem();
                x.UseSerilog();
                x.SetServiceName(assembly.GetName().Name);
                x.SetDisplayName(assembly.GetCustomAttribute<AssemblyTitleAttribute>().Title);
                x.SetDescription(assembly.GetCustomAttribute<AssemblyDescriptionAttribute>().Description);
                x.AddCommandLineDefinition("test", v => { isTest = true; } );
                x.AddCommandLineDefinition("config", v =>
                {
                    isTest = true;

                    //configure custom file
                    if (!string.IsNullOrEmpty(v))
                        Config.SetConfigFile(v);

                    Config.ConfigureAppSettings();
                });
                x.AddCommandLineDefinition("installAndConfigureService", v =>
                {
                    isTest = true;
                    Config.ConfigureAppSettings();
                    Config.InstallService();
                });
                x.AddCommandLineDefinition("uninstallService", v => Config.UninstallService(v));
                x.AddCommandLineDefinition("installAndConfigureInstance", v =>
                {
                    isTest = true;

                    if (string.IsNullOrEmpty(v))
                    {
                        Log.Logger.Error("Instance name must be provided");
                    }
                    else
                    {
                        Config.ConfigureFromFile();
                        Config.ConfigureAppSettings();
                        Config.InstallService(v);
                    }
                });
                x.AddCommandLineDefinition("loglevel", v =>
                {
                    var loggerConfig = new LoggerConfiguration();

                    try
                    {
                        switch (v)
                        {
                            case "information":
                                loggerConfig = loggerConfig.MinimumLevel.Information();
                                break;
                            case "warning":
                                loggerConfig = loggerConfig.MinimumLevel.Warning();
                                break;
                            case "debug":
                                loggerConfig = loggerConfig.MinimumLevel.Debug();
                                break;
                            case "error":
                                loggerConfig = loggerConfig.MinimumLevel.Error();
                                break;
                            case "verbose":
                                loggerConfig = loggerConfig.MinimumLevel.Verbose();
                                break;
                        }

                        Log.Logger = loggerConfig.WriteTo.Console()
                            .WriteTo.EventLog(AppName, manageEventSource: true)
                            .CreateLogger();
                    }
                    catch (SecurityException)
                    {
                        Log.Logger = loggerConfig.WriteTo.Console().CreateLogger();
                        Log.Warning("Unable to access Windows Event Log.  Logging console only");
                    }

                });
                x.EnableStartParameters();
                x.WithStartParameter("ConfigFile", f =>
                {
                    Config.SetConfigFile(f);
                });
                x.SetHelpTextPrefix(BuildHelpDoc());

            });

            var exitCode = (int)Convert.ChangeType(rc, rc.GetTypeCode());  
            Environment.ExitCode = exitCode;
        }

        private static string BuildHelpDoc()
        {
            var header = "\n------------------------------\n" +
                "Active Roles JIT Access for Safeguard Command-Line Reference\n" +
                "------------------------------\n\n";
            var test = "\t-test : tests the current configuration\n\n";
            var loglevel = "\t-loglevel : sets the log level for the application. Options: information, warning, debug, error, verbose. Defaults to information.\n\n";
            var config = "\t-config <file path>: launches configuration workflow and tests configuration. If no file path is provided, the default is used.\n\n";
            var installAndConfigureService = "\t-installAndConfigureService : launches configuration workflow, tests configuration, and installs service.\n\n";
            var installAndConfigureInstance = "\t-installAndConfigureInstance <name>: prompts for configuration file path, launches configuration workflow, " +
                "and installs service with specified instance name and config file parameter.\n\n";
            var configFile = "\t-ConfigFile : Specifies a custom config file for the service to use\n";
            var footer = "\n------------------------------\n";


            return string.Concat(new String[]{header,test,loglevel,config,installAndConfigureService,installAndConfigureInstance,configFile,footer});
        }
    }
}
