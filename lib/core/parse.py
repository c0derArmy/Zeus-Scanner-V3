import sys
from optparse import (
    OptionParser,
    OptionGroup,
    SUPPRESS_HELP
)

import lib.core.settings
import lib.core.common
import lib.core.errors


class ZeusParser(OptionParser):

    """
    Zeus's option parser - Advanced Bug Hunter & Pentester
    """

    def __init__(self):
        OptionParser.__init__(self)

    @staticmethod
    def cmd_parser():
        """
        command line parser, parses all of Zeus's arguments and flags
        """
        parser = OptionParser(usage="./zeus.py -u URL [OPTIONS]")

        mandatory = OptionGroup(parser, "Target",
                                "Specify your target")

        mandatory.add_option("-u", "--url", dest="singleTargetURL", metavar="URL",
                             help="Target URL to scan")

        mandatory.add_option("-f", "--url-file", dest="fileToEnumerate", metavar="FILE",
                             help="URLs file (one per line)")

        scan = OptionGroup(parser, "Scanning Modes",
                          "Choose scanning mode")

        scan.add_option("--autonomous", dest="autonomousMode", action="store_true",
                        help="Run fully autonomous security audit")

        scan.add_option("--full-scan", dest="fullScan", action="store_true",
                        help="Run comprehensive vulnerability scan")

        scan.add_option("--recon", dest="reconMode", action="store_true",
                        help="Reconnaissance mode only")

        ai = OptionGroup(parser, "AI Analysis",
                        "Free AI-powered analysis (Ollama/Groq)")

        ai.add_option("--ai-scan", dest="enableAIScan", action="store_true",
                       help="Enable AI vulnerability analysis")

        ai.add_option("--ai-provider", dest="aiProvider", metavar="PROVIDER",
                       help="AI provider: ollama, groq")

        ai.add_option("--ai-model", dest="aiModel", metavar="MODEL",
                       help="AI model name")

        ai.add_option("--ai-url", dest="aiUrl", metavar="URL",
                       help="Ollama URL (default: http://localhost:11434)")

        ai.add_option("--setup", dest="setupConfig", action="store_true",
                       help="Run interactive AI configuration setup")

        tools = OptionGroup(parser, "Security Tools",
                           "Integrated security tools")

        tools.add_option("--xsstrike", dest="runXsserScan", action="store_true",
                         help="XSS scanning with XSStrike")

        tools.add_option("--nuclei", dest="enableNucleiIntegration", action="store_true",
                         help="Nuclei vulnerability scanner")

        tools.add_option("--nuclei-severity", dest="nucleiSeverity", metavar="LEVEL",
                         help="Nuclei severity: critical,high,medium,low,info")

        tools.add_option("--sqlmap", dest="runSqliScan", action="store_true",
                         help="SQL injection scan with Sqlmap")

        tools.add_option("--nmap", dest="runPortScan", action="store_true",
                         help="Port scanning with Nmap")

        tools.add_option("--admin-panel", dest="adminPanelFinder", action="store_true",
                         help="Find admin/login panels")

        tools.add_option("--waf", dest="checkWafOnly", action="store_true",
                         help="WAF/IDS detection")

        tools.add_option("--crawler", dest="useKatana", action="store_true",
                         help="Web crawler (Katana)")

        cve = OptionGroup(parser, "CVE & Exploits",
                          "CVE scanning and exploit verification")

        cve.add_option("--sploit-scan", dest="runSploitScan", metavar="CVE-ID",
                       help="Scan specific CVE with SploitScan")

        cve.add_option("--cve-verify", dest="cveVerify", action="store_true",
                       help="Verify CVEs against target")

        cve.add_option("--exploit-db", dest="searchExploitDB", action="store_true",
                       help="Search ExploitDB for exploits")

        anon = OptionGroup(parser, "Anonymity",
                           "Proxy and identity")

        anon.add_option("--proxy", dest="proxyConfig", metavar="PROXY",
                        help="Proxy (http://proxy:port)")

        anon.add_option("--proxy-file", dest="proxyFileRand", metavar="FILE",
                        help="Load proxies from file")

        anon.add_option("--random-agent", dest="useRandomAgent", action="store_true",
                        help="Random user-agent")

        anon.add_option("--agent", dest="usePersonalAgent", metavar="AGENT",
                        help="Custom user-agent")

        misc = OptionGroup(parser, "General",
                           "Program behavior")

        misc.add_option("-v", "--verbose", dest="runInVerbose", action="store_true",
                        help="Verbose output")

        misc.add_option("-b", "--batch", dest="runInBatch", action="store_true",
                        help="Batch mode (no prompts)")

        misc.add_option("--hide", dest="hideBanner", action="store_true",
                        help="Hide banner")

        misc.add_option("--version", dest="showCurrentVersion", action="store_true",
                        help="Show version")

        misc.add_option("--timeout", dest="controlTimeout", metavar="SEC", type=int,
                        help="Request timeout")

        misc.add_option("--threads", dest="amountOfThreads", metavar="NUM", type=int,
                        help="Number of threads")

        parser.add_option_group(mandatory)
        parser.add_option_group(scan)
        parser.add_option_group(ai)
        parser.add_option_group(tools)
        parser.add_option_group(cve)
        parser.add_option_group(anon)
        parser.add_option_group(misc)

        opt, _ = parser.parse_args()
        return opt

    @staticmethod
    def single_show_args(opt):
        if opt.showCurrentVersion:
            print(lib.core.settings.VERSION_STRING)
            exit(0)

    @staticmethod
    def verify_args(args=sys.argv):
        pass
