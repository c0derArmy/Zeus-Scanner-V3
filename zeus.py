#!/usr/bin/env python3

import io
import sys
import time
import shlex
import warnings
import subprocess
import json

from var import blackwidow
from var.search import selenium_search
from var.auto_issue.github import request_issue_creation
from lib.header_check import main_header_check

from lib.core.parse import ZeusParser
from lib.core.errors import (
    InvalidInputProvided,
    InvalidProxyType,
    ZeusArgumentException
)
from lib.core.common import (
    start_up,
    shutdown,
    prompt
)
from lib.core.settings import (
    setup,
    logger,
    set_color,
    get_latest_log_file,
    get_random_dork,
    fix_log_file,
    config_headers,
    config_search_engine,
    find_running_opts,
    run_attacks,
    CURRENT_LOG_FILE_PATH,
    SPIDER_LOG_PATH,
    URL_REGEX, URL_QUERY_REGEX,
    URL_LOG_PATH,
    BANNER
)

# Import AI Engine and Integrations
try:
    from lib.ai_engine.ai_orchestrator import AIOrchestrator
    AI_ENGINE_AVAILABLE = True
except ImportError as e:
    AI_ENGINE_AVAILABLE = False
    print(f"Warning: AI Engine not available - {e}")

try:
    from lib.integrations.ai_orchestrator import EnhancedAIOrchestrator
    ENHANCED_AI_AVAILABLE = True
except ImportError as e:
    ENHANCED_AI_AVAILABLE = False
    print(f"Warning: Enhanced AI Orchestrator not available - {e}")

# REMOVED: ZAP, Burp, and Metasploit integrations (causing errors/hanging)
# Keeping only working AI-powered tools

# AI-Powered Tool Integrations
try:
    from lib.integrations.nuclei_integration import NucleiIntegration
    NUCLEI_INTEGRATION_AVAILABLE = True
except ImportError as e:
    NUCLEI_INTEGRATION_AVAILABLE = False
    print(f"Warning: Nuclei integration not available - {e}")

try:
    from lib.integrations.wapiti_integration import WapitiIntegration
    WAPITI_INTEGRATION_AVAILABLE = True
except ImportError as e:
    WAPITI_INTEGRATION_AVAILABLE = False
    print(f"Warning: Wapiti integration not available - {e}")

try:
    from lib.integrations.nikto_integration import NiktoIntegration
    NIKTO_INTEGRATION_AVAILABLE = True
except ImportError as e:
    NIKTO_INTEGRATION_AVAILABLE = False
    print(f"Warning: Nikto integration not available - {e}")

# REMOVED: AutoRecon integration (files deleted)
# AutoRecon functionality has been removed from Zeus Scanner


warnings.simplefilter("ignore")

if __name__ == "__main__":

    # Python 3 handles Unicode by default, no need for reload and setdefaultencoding
    sys.setrecursionlimit(1500)

    opt = ZeusParser.cmd_parser()

    ZeusParser().single_show_args(opt)

    # verify all the arguments passed before we continue
    # with the process
    ZeusParser().verify_args()

    # run the setup on the program
    setup(verbose=opt.runInVerbose)

    if not opt.hideBanner:
        print(BANNER)

    start_up()

    if opt.runInVerbose:
        being_run = find_running_opts(opt)
        logger.debug(set_color(
            "running with options '{}'".format(being_run), level=10
        ))

    logger.info(set_color(
        "log file being saved to '{}'".format(get_latest_log_file(CURRENT_LOG_FILE_PATH))
    ))


    def __run_attacks_main(**kwargs):
        """
        main method to run the attacks
        """
        log_to_use = kwargs.get("log", None)
        if log_to_use is None:
            options = (opt.dorkToUse, opt.useRandomDork, opt.dorkFileToUse)
            log_to_use = URL_LOG_PATH if any(o for o in options) else SPIDER_LOG_PATH
            try:
                urls_to_use = get_latest_log_file(log_to_use)
            except TypeError:
                urls_to_use = None
        else:
            urls_to_use = log_to_use

        if urls_to_use is None:
            logger.error(set_color(
                "unable to run attacks appears that no file was created for the retrieved data", level=40
            ))
            shutdown()
        options = [
            opt.runSqliScan, opt.runPortScan,
            opt.adminPanelFinder, opt.runXsserScan,
            opt.performWhoisLookup, opt.performClickjackingScan,
            opt.pgpLookup, opt.enableNucleiIntegration,
            opt.enableWapitiIntegration, opt.enableNiktoIntegration,
            opt.checkWafOnly
        ]
        if any(options):
            with open(urls_to_use, 'r', encoding='utf-8') as urls:
                for i, url in enumerate(urls.readlines(), start=1):
                    current = i
                    if "webcache" in url:
                        logger.warning(set_color(
                            "ran into unexpected webcache URL skipping", level=30
                        ))
                        current -= 1
                    else:
                        if not url.strip() == "http://" or url == "https://":
                            logger.info(set_color(
                                "currently running on '{}' (target #{})".format(
                                    url.strip(), current
                                ), level=25
                            ))
                            
                            # If only WAF check is requested, skip meta-data and run attacks
                            if opt.checkWafOnly:
                                logger.info(set_color(
                                    "performing WAF detection only (--check-waf)"
                                ))
                                from lib.core.wafw00f_integration import detect_waf_with_wafw00f
                                waf_result = detect_waf_with_wafw00f(
                                    url.strip(), 
                                    verbose=opt.runInVerbose, 
                                    proxy=proxy_to_use
                                )
                                if waf_result:
                                    logger.warning(set_color(
                                        "WAF/IDS/IPS detected: '{}'".format(waf_result), level=35
                                    ))
                                else:
                                    logger.info(set_color(
                                        "no WAF/IDS/IPS detected on target", level=25
                                    ))
                                print("\n")
                                continue
                            
                            logger.info(set_color(
                                "fetching target meta-data"
                            ))
                            identified = main_header_check(
                                url, verbose=opt.runInVerbose, agent=agent_to_use,
                                proxy=proxy_to_use, xforward=opt.forwardedForRandomIP,
                                identify_plugins=opt.identifyPlugin, identify_waf=True,
                                show_description=getattr(opt, 'showPluginDescription', False)
                            )
                            if not identified:
                                logger.error(set_color(
                                    "target is refusing to allow meta-data dumping, skipping", level=40
                                ))
                            run_attacks(
                                url.strip(),
                                sqlmap=opt.runSqliScan, nmap=opt.runPortScan, pgp=opt.pgpLookup,
                                xss=opt.runXsserScan, whois=opt.performWhoisLookup, admin=opt.adminPanelFinder,
                                clickjacking=opt.performClickjackingScan, github=getattr(opt, 'searchGithub', False),
                                verbose=opt.runInVerbose, batch=opt.runInBatch,
                                auto_start=opt.autoStartSqlmap, xforward=opt.forwardedForRandomIP,
                                sqlmap_args=opt.sqlmapArguments, nmap_args=opt.nmapArguments,
                                xsser_args=opt.xsserArguments,
                                show_all=opt.showAllConnections, do_threading=opt.threadPanels,
                                timeout=opt.controlTimeout,
                                proxy=proxy_to_use, agent=agent_to_use, conf_file=opt.sqlmapConfigFile,
                                threads=opt.amountOfThreads, force_ssl=opt.forceSSL,
                                use_nuclei=opt.enableNucleiIntegration,
                                use_wapiti=opt.enableWapitiIntegration,
                                use_nikto=opt.enableNiktoIntegration
                            )
                            print("\n")
                        else:
                            logger.warning(set_color(
                                "malformed URL discovered, skipping", level=30
                            ))


    proxy_to_use, agent_to_use = config_headers(
        proxy=opt.proxyConfig, proxy_file=opt.proxyFileRand,
        p_agent=opt.usePersonalAgent, rand_agent=opt.useRandomAgent,
        verbose=opt.runInVerbose
    )
    search_engine = config_search_engine(
        verbose=opt.runInVerbose, ddg=opt.useDDG,
        aol=opt.useAOL, bing=opt.useBing, enum=opt.fileToEnumerate
    )

    # Payload implementation handling - runs BEFORE main scanning logic
    # This allows exploit-mode to work alongside crawling and other attacks
    if AI_ENGINE_AVAILABLE and opt.implementPayloads:
        
        logger.info(set_color("starting payload implementation engine", level=25))
        
        # Initialize empty context for compatibility
        ai_context = {}
        
        # Determine target URL for payload implementation
        if opt.spiderWebSite:
            ai_target_url = opt.spiderWebSite
        elif opt.dorkToUse or opt.useRandomDork:
            # For dork-based scans, we'll let the AI engine work with discovered URLs
            ai_target_url = None
        elif opt.fileToEnumerate:
            # For file enumeration, use the first URL as base target
            try:
                with open(opt.fileToEnumerate, 'r') as f:
                    first_url = f.readline().strip()
                    ai_target_url = first_url if first_url else None
            except:
                ai_target_url = None
        else:
            logger.error(set_color("AI assessment requires a target URL or website to analyze", level=40))
            shutdown()
        
        # Initialize AI orchestrator
        if ai_target_url:
            ai_orchestrator = AIOrchestrator(
                target_url=ai_target_url,
                verbose=opt.runInVerbose,
                user_agent=agent_to_use,
                proxy=proxy_to_use,
                context=ai_context
            )
            
            try:
                # Execute payload implementation based on selected mode
                if opt.implementPayloads:
                    logger.info(set_color("="*80, level=25))
                    logger.info(set_color("STARTING ACTIVE PAYLOAD IMPLEMENTATION MODE", level=25))
                    logger.info(set_color("WARNING: This will ACTIVELY test all fetched payloads against target", level=30))
                    logger.info(set_color("="*80, level=25))
                    
                    # Import the active exploitation engine
                    try:
                        from lib.attacks.active_exploitation.exploit_orchestrator import ExploitOrchestrator
                        
                        # Configure exploit settings based on options
                        exploit_config = {
                            'user_agent': agent_to_use,
                            'proxy': proxy_to_use,
                            'timeout': 30,
                            'delay': 0.1 if opt.fastPayloadMode else 0.5,
                            'enable_exploitation': opt.implementPayloads,
                            'comprehensive_mode': opt.comprehensivePayloadMode,
                            'fast_mode': opt.fastPayloadMode
                        }
                        
                        orchestrator = ExploitOrchestrator(exploit_config)
                        
                        # Get fetched payloads from AI engine
                        logger.info(set_color("Fetching latest payloads from online sources for implementation...", level=25))

                        try:
                            # Get the fetched payloads from the already initialized AI orchestrator
                            fetched_payloads = ai_orchestrator.enhanced_ai.payload_fetcher.fetched_data

                            logger.info(set_color(f"Payloads ready for implementation:", level=25))
                            for payload_type, payloads in fetched_payloads.items():
                                if payloads:
                                    logger.info(set_color(f"  {payload_type}: {len(payloads)} payloads", level=25))
                        except Exception as e:
                            logger.warning(set_color(f"Could not access fetched payloads directly: {str(e)}", level=30))
                        
                        # EXECUTE THE COMPLETE PAYLOAD IMPLEMENTATION
                        logger.info(set_color("Starting comprehensive payload implementation against target...", level=25))
                        
                        implementation_results = orchestrator.orchestrate_complete_implementation(
                            ai_target_url, 
                            fetched_payloads
                        )
                        
                        # Display comprehensive results
                        logger.info(set_color("="*80, level=25))
                        logger.info(set_color("PAYLOAD IMPLEMENTATION RESULTS", level=25))
                        logger.info(set_color("="*80, level=25))
                        
                        summary = implementation_results.get('summary', {})
                        
                        print(f"\n{set_color('IMPLEMENTATION SUMMARY:', level=25)}")
                        print(f"Target: {implementation_results.get('target', 'Unknown')}")
                        print(f"Total Payloads Executed: {summary.get('total_payloads_executed', 0)}")
                        print(f"Successful Exploits: {summary.get('successful_exploits', 0)}")
                        print(f"System Compromise Level: {summary.get('system_compromise_level', 'none').upper()}")
                        print(f"Persistence Achieved: {'YES' if summary.get('persistence_achieved') else 'NO'}")
                        print(f"Data Extracted: {'YES' if summary.get('data_extracted') else 'NO'}")
                        
                        # Show phase results
                        phases = implementation_results.get('phases', {})
                        
                        if 'phase1_payload_execution' in phases:
                            phase1 = phases['phase1_payload_execution']
                            print(f"\n{set_color('PHASE 1 - Online Payload Execution:', level=35)}")
                            print(f"  Payloads Executed: {phase1.get('payloads_executed', 0)}")
                            print(f"  Vulnerabilities Found: {len(phase1.get('vulnerabilities_found', []))}")
                            
                            # Show found vulnerabilities
                            for vuln in phase1.get('vulnerabilities_found', []):
                                print(f"    [{vuln['severity'].upper()}] {vuln['type']}")
                        
                        if 'phase2_vulnerability_implementation' in phases:
                            phase2 = phases['phase2_vulnerability_implementation']
                            print(f"\n{set_color('PHASE 2 - Advanced Vulnerability Implementation:', level=35)}")
                            print(f"  Successful Implementations: {len(phase2.get('successful_implementations', []))}")
                            print(f"  Advanced Techniques Used: {len(phase2.get('advanced_techniques_used', []))}")
                        
                        if 'phase3_exploitation_chain' in phases:
                            phase3 = phases['phase3_exploitation_chain']  
                            print(f"\n{set_color('PHASE 3 - Exploitation Chains:', level=35)}")
                            print(f"  Chains Created: {phase3.get('chains_created', 0)}")
                            print(f"  Successful Chains: {phase3.get('successful_chains', 0)}")
                            print(f"  Maximum Compromise: {'YES' if phase3.get('maximum_compromise_achieved') else 'NO'}")
                        
                        if 'phase4_persistence_establishment' in phases:
                            phase4 = phases['phase4_persistence_establishment']
                            print(f"\n{set_color('PHASE 4 - Persistence Establishment:', level=35)}")
                            print(f"  Persistence Methods: {len(phase4.get('successful_persistence', []))}")
                            print(f"  Backup Access Points: {len(phase4.get('backup_access_points', []))}")
                        
                        # Show execution time
                        duration = implementation_results.get('total_duration', 0)
                        print(f"\n{set_color('Assessment Duration:', level=25)} {duration:.2f} seconds")
                        
                        # Display report location
                        print(f"\n{set_color('Reports Generated:', level=25)}")
                        print(f"  Complete implementation reports saved in current directory")
                        print(f"  Look for files: complete_payload_implementation_report_*.json/html")
                        
                        logger.info(set_color("="*80, level=25))
                        logger.info(set_color("ACTIVE PAYLOAD IMPLEMENTATION COMPLETED", level=25))
                        logger.info(set_color("="*80, level=25))
                        
                    except ImportError as e:
                        logger.error(set_color(f"Active exploitation engine not available: {str(e)}", level=40))
                        logger.info(set_color("Make sure all dependencies are installed", level=25))
                    
                    except Exception as e:
                        logger.error(set_color(f"Payload implementation failed: {str(e)}", level=40))
                        if opt.runInVerbose:
                            import traceback
                            traceback.print_exc()
                
                # Continue to crawling and further attacks instead of exiting
                logger.info(set_color("Continuing with web crawler and attack modules...", level=25))
                
            except Exception as e:
                logger.error(set_color(f"AI assessment failed: {e}", level=40))
                if opt.runInVerbose:
                    import traceback
                    traceback.print_exc()
                shutdown()
        else:
            logger.error(set_color("no valid target URL found for AI assessment", level=40))
            shutdown()


    
    if not AI_ENGINE_AVAILABLE and opt.implementPayloads:
        logger.error(set_color("Payload implementation engine is not available. Please install required dependencies: pip3 install -r requirements.txt", level=40))
        shutdown()

    # Main scanning and attack logic - executes regardless of payload implementation
    try:
        # use a personal dork as the query
        if opt.dorkToUse is not None and not opt.searchMultiplePages:
            logger.info(set_color(
                "starting dork scan with query '{}'".format(opt.dorkToUse)
            ))
            try:
                selenium_search.parse_search_results(
                    opt.dorkToUse, search_engine, verbose=opt.runInVerbose, proxy=proxy_to_use,
                    agent=agent_to_use, pull_all=opt.noExclude, parse_webcache=opt.parseWebcache,
                    forward_for=opt.forwardedForRandomIP, tor=opt.useTor, batch=opt.runInBatch,
                    show_success=getattr(opt, 'showSuccessRate', False)
                )
            except InvalidProxyType:
                supported_proxy_types = ("socks5", "socks4", "https", "http")
                logger.fatal(set_color(
                    "the provided proxy is not valid, specify the protocol and try again, supported "
                    "proxy protocols are {} (IE socks5://127.0.0.1:9050)".format(
                        ", ".join(list(supported_proxy_types))), level=50
                ))
            except Exception as e:
                if "Permission denied:" in str(e):
                    logger.fatal(set_color(
                        "your permissions are not allowing Zeus to run, "
                        "try running Zeus with sudo", level=50
                    ))
                    shutdown()
                else:
                    logger.exception(set_color(
                        "ran into exception '{}'".format(e), level=50
                    ))
                if not opt.runInBatch:
                    request_issue_creation()
                pass

            __run_attacks_main()

        # search multiple pages of Google
        elif opt.dorkToUse is not None or opt.useRandomDork and opt.searchMultiplePages:
            if opt.dorkToUse is not None:
                dork_to_use = opt.dorkToUse
            elif opt.useRandomDork:
                dork_to_use = get_random_dork()
            else:
                dork_to_use = None

            if dork_to_use is None:
                logger.warning(set_color(
                    "there has been no dork to specified to do the searching, defaulting to random dork", level=30
                ))
                dork_to_use = get_random_dork()

            dork_to_use = dork_to_use.strip()

            if opt.amountToSearch is None:
                logger.warning(set_color(
                    "did not specify amount of links to find defaulting to 75", level=30
                ))
                link_amount_to_search = 75
            else:
                link_amount_to_search = opt.amountToSearch

            logger.info(set_color(
                "searching Google using dork '{}' for a total of {} links".format(
                    dork_to_use, link_amount_to_search
                )
            ))
            try:
                selenium_search.search_multiple_pages(
                    dork_to_use, link_amount_to_search, proxy=proxy_to_use,
                    agent=agent_to_use, verbose=opt.runInVerbose,
                    xforward=opt.forwardedForRandomIP, batch=opt.runInBatch,
                    show_success=getattr(opt, 'showSuccessRate', False)
                )
            except Exception as e:
                if "Error 400" in str(e):
                    logger.fatal(set_color(
                        "failed to connect to search engine".format(e), level=50
                    ))
                else:
                    logger.exception(set_color(
                        "failed with unexpected error '{}'".format(e), level=50
                    ))
                shutdown()

            __run_attacks_main()

        # use a file full of dorks as the queries
        elif opt.dorkFileToUse is not None:
            with io.open(opt.dorkFileToUse, encoding="utf-8") as dorks:
                for dork in dorks.readlines():
                    dork = dork.strip()
                    logger.info(set_color(
                        "starting dork scan with query '{}'".format(dork)
                    ))
                    try:
                        selenium_search.parse_search_results(
                            dork, search_engine, verbose=opt.runInVerbose, proxy=proxy_to_use,
                            agent=agent_to_use, pull_all=opt.noExclude, parse_webcache=opt.parseWebcache,
                            tor=opt.useTor, batch=opt.runInBatch
                        )
                    except Exception as e:
                        logger.exception(set_color(
                            "ran into exception '{}'".format(e), level=50
                        ))
                        if not opt.runInBatch:
                            request_issue_creation()
                        pass

            __run_attacks_main()

        # use a random dork as the query
        elif opt.useRandomDork:
            random_dork = get_random_dork().strip()
            if opt.runInVerbose:
                logger.debug(set_color(
                    "choosing random dork from etc/dorks.txt", level=10
                ))
            logger.info(set_color(
                "using random dork '{}' as the search query".format(random_dork)
            ))
            try:
                selenium_search.parse_search_results(
                    random_dork, search_engine, verbose=opt.runInVerbose,
                    proxy=proxy_to_use, agent=agent_to_use, pull_all=opt.noExclude, parse_webcache=opt.parseWebcache,
                    tor=opt.useTor, batch=opt.runInBatch
                )
                __run_attacks_main()

            except Exception as e:
                if not opt.runInBatch:
                    request_issue_creation()
                pass

        # spider a given webpage for all available URL's
        elif opt.spiderWebSite:
            problem_identifiers = ["http://", "https://"]
            if not URL_REGEX.match(opt.spiderWebSite):
                err_msg = "URL did not match a true URL{}"
                if not any(m in opt.spiderWebSite for m in problem_identifiers):
                    err_msg = err_msg.format(" issue seems to be that http:// "
                                             "or https:// is not present in the URL")
                else:
                    err_msg = err_msg.format("")
                raise InvalidInputProvided(
                    err_msg
                )
            else:
                if URL_QUERY_REGEX.match(opt.spiderWebSite):
                    question_msg = (
                        "it is recommended to not use a URL that has a GET(query) parameter in it, "
                        "would you like to continue"
                    )
                    if not opt.runInBatch:
                        is_sure = prompt(
                            question_msg, opts="yN"
                        )
                    else:
                        is_sure = prompt(
                            question_msg, opts="yN", default="y"
                        )
                    if is_sure.lower().startswith("y"):
                        pass
                    else:
                        shutdown()

            # Validate and set crawl delay
            crawl_delay = opt.crawlDelay if hasattr(opt, 'crawlDelay') and opt.crawlDelay else 0.1
            # Ensure delay is within reasonable bounds
            crawl_delay = max(0.05, min(5.0, crawl_delay))

            blackwidow.blackwidow_main(opt.spiderWebSite, agent=agent_to_use, proxy=proxy_to_use,
                                       verbose=opt.runInVerbose, forward=opt.forwardedForRandomIP, 
                                       crawl_delay=crawl_delay)

            __run_attacks_main()

        # enumerate a file and run attacks on the URL's provided
        elif opt.fileToEnumerate is not None:
            logger.info(set_color(
                "found a total of {} URL's to enumerate in given file".format(
                    len(open(opt.fileToEnumerate).readlines())
                )
            ))
            __run_attacks_main(log=opt.fileToEnumerate)

        else:
            logger.critical(set_color(
                "failed to provide a mandatory argument, you will be redirected to the help menu", level=50
            ))
            time.sleep(2)
            zeus_help_menu_command = shlex.split("python3 zeus.py --help")
            subprocess.call(zeus_help_menu_command)
    except IOError as e:
        if "Invalid URL" in str(e):
            logger.exception(set_color(
                "URL provided is not valid, schema appears to be missing", level=50
            ))
            if not opt.runInBatch:
                request_issue_creation()
            shutdown()
        elif "HTTP Error 429: Too Many Requests" in str(e):
            logger.fatal(set_color(
                "WhoIs doesn't like it when you send to many requests at one time, "
                "try updating the timeout with the --time-sec flag (IE --time-sec 10)", level=50
            ))
            shutdown()
        elif "No such file or directory" in str(e):
            logger.fatal(set_color(
                "provided file does not exist, make sure you have the full path", level=50
            ))
            shutdown()
        else:
            logger.exception(set_color(
                "Zeus has hit an unexpected error and cannot continue, error code '{}'".format(e), level=50
            ))
            request_issue_creation()
    except KeyboardInterrupt:
        logger.fatal(set_color(
            "user aborted process", level=50
        ))
        shutdown()
    except UnboundLocalError:
        logger.warning(set_color(
            "do not interrupt the browser when selenium is running, "
            "it will cause Zeus to crash", level=30
        ))
    except ZeusArgumentException:
        shutdown()
    except Exception as e:
        if "url did not match a true url" in str(e).lower():
            logger.error(set_color(
                "you did not provide a URL that is capable of being processed, "
                "the URL provided to the spider needs to contain protocol as well "
                "ie. 'http://google.com' (it is advised not to add the GET parameter), "
                "fix the URL you want to scan and try again", level=40
            ))
            shutdown()
        elif "Service geckodriver unexpectedly exited" in str(e):
            logger.fatal(set_color(
                "it seems your firefox version is not compatible with the geckodriver version, "
                "please re-install Zeus and try again", level=50
            ))
            shutdown()
        elif "Max retries exceeded with url" in str(e):
            logger.fatal(set_color(
                "you have hit the max retries, to continue using Zeus "
                "it is recommended to use a proxy (--proxy/--proxy-file) "
                "along with a new user-agent (--random-agent/--agent).", level=50
            ))
            shutdown()
        else:
            logger.exception(set_color(
                "ran into exception '{}' exception has been saved to log file".format(e), level=50
            ))
            request_issue_creation()

    # fix the log file before shutting down incase you want to look at it
    fix_log_file()
shutdown()