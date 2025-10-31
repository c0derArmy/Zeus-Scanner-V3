import json
import socket

# Make nmap optional
NMAP_AVAILABLE = False
try:
    import nmap
    # Try to initialize nmap without raising an error
    try:
        test_scanner = nmap.PortScanner()
        NMAP_AVAILABLE = True
    except Exception as e:
        print(f"Warning: nmap program not found. Nmap scanning functionality will be disabled. Error: {str(e)}")
except ImportError:
    print("Warning: nmap module not found. Nmap scanning functionality will be disabled.")

import lib.core.common
import lib.core.errors
import lib.core.settings
import lib.core.decorators
from var.auto_issue.github import request_issue_creation


class NmapHook(object):

    """
    Nmap API hook, uses python, must have nmap on your system
    """

    # Initialize NM as None by default
    NM = None
    
    # Only set NM if nmap is available
    if NMAP_AVAILABLE:
        try:
            NM = nmap.PortScanner()
        except:
            pass

    def __init__(self, ip, **kwargs):
        self.ip = ip
        self.verbose = kwargs.get("verbose", False)
        self.pretty = kwargs.get("pretty", True)
        self.dir = lib.core.settings.PORT_SCAN_LOG_PATH
        self.file = lib.core.settings.NMAP_FILENAME
        self.opts = kwargs.get("opts", "")
        
        # Check if nmap is available
        if not NMAP_AVAILABLE:
            lib.core.settings.logger.error("Nmap is not available, scanning functionality will be disabled")

    def get_all_info(self):
        """
        get all the information from the scan
        """
        # Check if nmap is available before proceeding
        if not NMAP_AVAILABLE:
            lib.core.settings.logger.error("Nmap is not available, cannot perform scan")
            return None
        if isinstance(self.opts, (list, tuple)):
            self.opts = ""
        scanned_data = self.NM.scan(self.ip, arguments=self.opts)
        if self.pretty:
            scanned_data = json.dumps(scanned_data, indent=4, sort_keys=True)
        return scanned_data

    def send_to_file(self, data):
        """
        send all the information to a JSON file for further use
        """
        return lib.core.common.write_to_log_file(
            data, lib.core.settings.NMAP_LOG_FILE_PATH,
            lib.core.settings.NMAP_FILENAME.format(self.ip)
        )

    def show_open_ports(self, json_data, sep="-" * 30):
        """
        outputs the current scan information with colorful display
        """
        # have to create a spacer or the output comes out funky..
        spacer_data = {4: " " * 8, 6: " " * 6, 8: " " * 4}
        
        # Colorful header
        print(lib.core.settings.set_color("\n" + "=" * 60, level=25))
        print(lib.core.settings.set_color("         NMAP PORT SCAN RESULTS", level=30))
        print(lib.core.settings.set_color("=" * 60, level=25))
        
        lib.core.settings.logger.info(lib.core.settings.set_color("finding data for IP '{}'".format(self.ip)))
        json_data = json.loads(json_data)["scan"]
        host = json_data[self.ip]["hostnames"][0]["name"]
        host_skip = (not len(host) == 0, " ", "", None)
        
        # Colorful scan info
        status_color = 25 if json_data[self.ip]["status"]["state"] == "up" else 40
        print(f"{lib.core.settings.set_color('Target:', level=20)} {lib.core.settings.set_color(self.ip, level=35)}")
        print(f"{lib.core.settings.set_color('Hostname:', level=20)} {lib.core.settings.set_color(host if host != any(s for s in list(host_skip)) else 'unknown', level=35)}")
        print(f"{lib.core.settings.set_color('Status:', level=20)} {lib.core.settings.set_color(json_data[self.ip]['status']['state'], level=status_color)}")
        print(f"{lib.core.settings.set_color('Protocol:', level=20)} {lib.core.settings.set_color('TCP', level=15)}")
        print(lib.core.settings.set_color("-" * 60, level=25))
        
        oports = list(json_data[self.ip]["tcp"].keys())
        oports.sort(key=int)
        
        # Count open/closed ports for summary
        open_ports = 0
        closed_ports = 0
        filtered_ports = 0
        
        print(lib.core.settings.set_color("PORT SCAN DETAILS:", level=30))
        print(lib.core.settings.set_color("-" * 60, level=25))
        
        for port in oports:
            port_status = json_data[self.ip]["tcp"][port]["state"]
            service_name = json_data[self.ip]["tcp"][port]["name"]
            
            # Color code based on port status
            if port_status == "open":
                status_color = 40  # Red for open (potential security risk)
                open_ports += 1
            elif port_status == "closed":
                status_color = 15  # Cyan for closed
                closed_ports += 1
            else:
                status_color = 30  # Yellow for filtered/unknown
                filtered_ports += 1
            
            # Colorful port output
            print(f"{lib.core.settings.set_color(f'Port {port}:', level=20)} "
                  f"{lib.core.settings.set_color(port_status.upper(), level=status_color)} "
                  f"({lib.core.settings.set_color(service_name, level=35)})")
        
        # Colorful summary
        print(lib.core.settings.set_color("-" * 60, level=25))
        print(lib.core.settings.set_color("SCAN SUMMARY:", level=30))
        print(f"{lib.core.settings.set_color('Open Ports:', level=20)} {lib.core.settings.set_color(str(open_ports), level=40 if open_ports > 0 else 15)}")
        print(f"{lib.core.settings.set_color('Closed Ports:', level=20)} {lib.core.settings.set_color(str(closed_ports), level=15)}")
        print(f"{lib.core.settings.set_color('Filtered Ports:', level=20)} {lib.core.settings.set_color(str(filtered_ports), level=30)}")
        print(f"{lib.core.settings.set_color('Total Scanned:', level=20)} {lib.core.settings.set_color(str(len(oports)), level=25)}")
        
        if open_ports > 0:
            print(f"{lib.core.settings.set_color('Security Risk:', level=20)} {lib.core.settings.set_color('HIGH - Open ports detected!', level=40)}")
        else:
            print(f"{lib.core.settings.set_color('Security Risk:', level=20)} {lib.core.settings.set_color('LOW - No open ports found', level=15)}")
            
        print(lib.core.settings.set_color("=" * 60, level=25))


def find_nmap(item_name="nmap"):
    """
    find nmap on the users system if they do not specify a path for it or it is not in their PATH
    """
    return lib.core.settings.find_application(item_name)


def perform_port_scan(url, scanner=NmapHook, **kwargs):
    """
    main function that will initalize the port scanning
    """
    verbose = kwargs.get("verbose", False)
    opts = kwargs.get("opts", None)
    timeout_time = kwargs.get("timeout", None)

    if timeout_time is None:
        timeout_time = 120

    with lib.core.decorators.TimeOut(seconds=timeout_time):
        lib.core.settings.logger.warning(lib.core.settings.set_color(
            "if the port scan is not completed in {}(m) it will timeout".format(
                lib.core.settings.convert_to_minutes(timeout_time)
            ), level=30
        ))
        url = url.strip()
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "attempting to find IP address for hostname '{}'".format(url)
        ))

        try:
            found_ip_address = socket.gethostbyname(url)
        except socket.gaierror:
            lib.core.settings.logger.fatal(lib.core.settings.set_color(
                "failed to gather IP address for URL '{}'".format(url)
            ))
            return

        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "checking for nmap on your system", level=10
            ))
        nmap_exists = "".join(find_nmap())
        if nmap_exists:
            if verbose:
                lib.core.settings.logger.debug(lib.core.settings.set_color(
                    "nmap has been found under '{}'".format(nmap_exists), level=10
                ))
            lib.core.settings.logger.info(lib.core.settings.set_color(
                "starting port scan on IP address '{}'".format(found_ip_address)
            ))
            try:
                data = scanner(found_ip_address, opts=opts)
                json_data = data.get_all_info()
                data.show_open_ports(json_data)
                file_path = data.send_to_file(json_data)
                lib.core.settings.logger.info(lib.core.settings.set_color(
                    "port scan completed, all data saved to JSON file under '{}'".format(file_path)
                ))
            except KeyError:
                lib.core.settings.logger.fatal(lib.core.settings.set_color(
                    "no port information found for '{}({})'".format(
                        url, found_ip_address
                    ), level=50
                ))
            except KeyboardInterrupt:
                if not lib.core.common.pause():
                    lib.core.common.shutdown()
            except lib.core.errors.PortScanTimeOutException:
                lib.core.settings.logger.error(lib.core.settings.set_color(
                    "port scan is taking to long and has hit the timeout, you "
                    "can increase this time by passing the --time-sec flag (IE "
                    "--time-sec 300)", level=40
                ))
            except Exception as e:
                lib.core.settings.logger.exception(lib.core.settings.set_color(
                    "ran into exception '{}', cannot continue quitting".format(e), level=50
                ))
                request_issue_creation()
                pass
        else:
            lib.core.settings.logger.fatal(lib.core.settings.set_color(
                "nmap was not found on your system", level=50
            ))
            lib.core.common.run_fix(
                "would you like to automatically install it",
                "sudo sh {}".format(lib.core.settings.NMAP_INSTALLER_TOOL),
                "nmap is not installed, please install it in order to continue"
            )