import os
import time
import urllib.parse

from bs4 import BeautifulSoup

try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)  # Initialize colorama
except ImportError:
    # Fallback if colorama is not installed
    class Fore:
        RED = '\033[31m'
        GREEN = '\033[32m'
        YELLOW = '\033[33m'
        BLUE = '\033[34m'
        MAGENTA = '\033[35m'
        CYAN = '\033[36m'
        WHITE = '\033[37m'
        RESET = '\033[0m'
    
    class Style:
        BRIGHT = '\033[1m'
        RESET_ALL = '\033[0m'

import lib.core.errors
import lib.core.common
import lib.core.settings
import var.auto_issue.github


class Blackwidow(object):

    """
    spider to scrape a webpage for all available URL's
    """

    def __init__(self, url, user_agent=None, proxy=None, forward=None):
        self.url = url
        self.forward = forward or None
        self.proxy = proxy
        self.user_agent = user_agent or lib.core.settings.DEFAULT_USER_AGENT

    @staticmethod
    def get_url_ext(url):
        """
        get the extension of the URL
        """
        try:
            data = url.split(".")
            return data[-1] in lib.core.settings.SPIDER_EXT_EXCLUDE
        except (IndexError, Exception):
            pass

    def test_connection(self):
        """
        make sure the connection is good before you continue
        """
        try:
            # we'll skip SSL verification to avoid any SSLErrors that might
            # arise, we won't really need it with this anyways
            attempt, status, _, _ = lib.core.common.get_page(
                self.url, agent=self.user_agent, xforward=self.forward, skip_verf=True,
                proxy=self.proxy
            )
            if status == 200:
                return "ok", None
            return "fail", attempt.status_code
        except Exception as e:
            if "Max retries exceeded with url" in str(e):
                info_msg = ""
                if "https://" in self.url:
                    info_msg += ", try dropping https:// to http://"
                else:
                    info_msg += ""
                lib.core.settings.logger.fatal(lib.core.settings.set_color(
                    "provided website '{}' is refusing connection{}".format(
                        self.url, info_msg
                    ), level=50
                ))
                lib.core.common.shutdown()
            else:
                lib.core.settings.logger.exception(lib.core.settings.set_color(
                    "failed to connect to '{}' received error '{}'".format(
                        self.url, e
                    ), level=50
                ))
                var.auto_issue.github.request_issue_creation()
                lib.core.common.shutdown()

    def scrape_page_for_links(self, given_url, attribute="a", descriptor="href", delay=0.1):
        """
        scrape the webpage's HTML for usable GET links
        """
        unique_links = set()
        true_url = lib.core.settings.replace_http(given_url)
        _, status, html_page, _ = lib.core.common.get_page(
            given_url, agent=self.user_agent, proxy=self.proxy
        )
        soup = BeautifulSoup(html_page, "html.parser")
        
        # Simple Blackwidow Crawler Display
        print(f"\n{Fore.CYAN}Zeus Blackwidow Crawler Started{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Target: {Fore.WHITE}{given_url}{Style.RESET_ALL}")
        print(f"{Fore.BLUE}Crawl delay: {Fore.WHITE}{delay}s per URL{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
        
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "starting blackwidow crawler on '{}'".format(self.url), level=25
        ))
        
        # Categorize URLs for colored display
        pdf_links = []
        external_links = []
        internal_links = []
        other_links = []
        subdomain_links = []
        
        for i, link in enumerate(soup.findAll(attribute), 1):
            found_redirect = str(link.get(descriptor))
            if found_redirect is not None and found_redirect != "None":
                # Handle relative URLs
                if found_redirect.startswith('/'):
                    found_redirect = urllib.parse.urljoin(given_url, found_redirect)
                elif not found_redirect.startswith(('http://', 'https://', 'ftp://', 'mailto:')):
                    if found_redirect.startswith('#') or found_redirect.startswith('javascript:'):
                        continue  # Skip anchors and javascript
                    found_redirect = urllib.parse.urljoin(given_url, found_redirect)
                
                # Only process HTTP/HTTPS URLs
                if not (found_redirect.startswith('http://') or found_redirect.startswith('https://')):
                    continue
                
                if lib.core.settings.URL_REGEX.match(found_redirect):
                    unique_links.add(found_redirect)
                    
                    # Parse domain for categorization
                    parsed_url = urllib.parse.urlparse(found_redirect)
                    parsed_target = urllib.parse.urlparse(given_url)
                    
                    # Categorize and color-code URLs
                    if found_redirect.lower().endswith(('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx')):
                        pdf_links.append(found_redirect)
                        color = Fore.RED
                        link_type = "[DOC]"
                    elif parsed_url.netloc != parsed_target.netloc:
                        if parsed_url.netloc.endswith('.' + parsed_target.netloc):
                            # Subdomain
                            subdomain_links.append(found_redirect)
                            color = Fore.MAGENTA
                            link_type = "[SUB]"
                        else:
                            # External domain
                            external_links.append(found_redirect)
                            color = Fore.YELLOW
                            link_type = "[EXT]"
                    else:
                        # Internal page
                        internal_links.append(found_redirect)
                        color = Fore.GREEN
                        link_type = "[INT]"
                    
                    # Display URL in color with category
                    print(f"{color}{link_type} {found_redirect}{Style.RESET_ALL}")
                else:
                    # Try to construct full URL for relative paths
                    if not found_redirect.startswith(('http://', 'https://')):
                        full_url = urllib.parse.urljoin(given_url, found_redirect)
                        if lib.core.settings.URL_REGEX.match(full_url):
                            unique_links.add(full_url)
                            other_links.append(full_url)
                            print(f"{Fore.CYAN}[REL] {full_url}{Style.RESET_ALL}")
            
            time.sleep(delay)
        
        # Simple Summary with color coding
        print(f"\n{Fore.YELLOW}{'='*80}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Crawl Summary{Style.RESET_ALL}")
        print(f"{Fore.GREEN}Internal Links: {len(internal_links)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}External Links: {len(external_links)}{Style.RESET_ALL}")
        print(f"{Fore.MAGENTA}Subdomain Links: {len(subdomain_links)}{Style.RESET_ALL}")
        print(f"{Fore.RED}Document Links: {len(pdf_links)}{Style.RESET_ALL}")
        print(f"{Fore.CYAN}Other Links: {len(other_links)}{Style.RESET_ALL}")
        print(f"{Fore.WHITE}Total Unique URLs: {len(unique_links)}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}{'='*80}{Style.RESET_ALL}\n")
        
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "blackwidow crawl complete: {} URLs discovered".format(len(unique_links)), level=25
        ))
        
        return list(unique_links)


def blackwidow_main(url, **kwargs):
    """
    scrape a given URL for all available links
    """
    verbose = kwargs.get("verbose", False)
    proxy = kwargs.get("proxy", None)
    agent = kwargs.get("agent", None)
    forward = kwargs.get("forward", None)
    crawl_delay = kwargs.get("crawl_delay", 0.1)  # Default 0.1 second delay

    if forward is not None:
        forward = (
            lib.core.settings.create_random_ip(),
            lib.core.settings.create_random_ip(),
            lib.core.settings.create_random_ip()
        )

    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "settings user-agent to '{}'".format(agent), level=10
        ))
    if proxy is not None:
        if verbose:
            lib.core.settings.logger.debug(lib.core.settings.set_color(
                "running behind proxy '{}'".format(proxy), level=10
            ))
    
    # Create enhanced log directory structure
    log_base_dir = "{}/{}".format(os.getcwd(), "log/blackwidow-log")
    lib.core.settings.create_dir(log_base_dir)
    
    # Create timestamp-based subdirectory
    timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
    scan_dir = "{}/scan_{}".format(log_base_dir, timestamp)
    lib.core.settings.create_dir(scan_dir)
    
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "starting blackwidow on '{}'".format(url)
    ))
    crawler = Blackwidow(url, user_agent=agent, proxy=proxy, forward=forward)
    if verbose:
        lib.core.settings.logger.debug(lib.core.settings.set_color(
            "testing connection to the URL", level=10
        ))
    test_code = crawler.test_connection()
    if not test_code[0] == "ok":
        error_msg = (
            "connection test failed with status code: {}, reason: '{}'. "
            "test connection needs to pass, try a different link"
        )
        for error_code in lib.core.common.STATUS_CODES.keys():
            if error_code == test_code[1]:
                lib.core.settings.logger.fatal(lib.core.settings.set_color(
                    error_msg.format(
                        test_code[1], lib.core.common.STATUS_CODES[error_code].title()
                    ), level=50
                ))
                lib.core.common.shutdown()
        lib.core.settings.logger.fatal(lib.core.settings.set_color(
            error_msg.format(
                test_code[1], lib.core.common.STATUS_CODES["other"].title()
            ), level=50
        ))
        lib.core.common.shutdown()
    else:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "connection test succeeded, continuing", level=25
        ))
    lib.core.settings.logger.info(lib.core.settings.set_color(
        "crawling given URL '{}' for links".format(url)
    ))
    found = crawler.scrape_page_for_links(url, delay=crawl_delay)
    if len(found) > 0:
        lib.core.settings.logger.info(lib.core.settings.set_color(
            "found a total of {} links from given URL '{}'".format(
                len(found), url
            ), level=25
        ))
        
        # Enhanced saving with categorization
        save_enhanced_results(found, url, scan_dir, timestamp)
        
        # Also save to the default location for compatibility
        lib.core.common.write_to_log_file(found, path=lib.core.settings.SPIDER_LOG_PATH,
                                          filename=lib.core.settings.BLACKWIDOW_FILENAME)
    else:
        lib.core.settings.logger.fatal(lib.core.settings.set_color(
            "did not find any usable links from '{}'".format(url), level=50
        ))


def save_enhanced_results(found_links, target_url, scan_dir, timestamp):
    """
    Save crawled results in multiple enhanced formats
    """
    # Categorize links
    internal_links = []
    external_links = []
    subdomain_links = []
    document_links = []
    other_links = []
    
    parsed_target = urllib.parse.urlparse(target_url)
    
    for link in found_links:
        parsed_link = urllib.parse.urlparse(link)
        
        if link.lower().endswith(('.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.zip', '.rar')):
            document_links.append(link)
        elif parsed_link.netloc == parsed_target.netloc:
            internal_links.append(link)
        elif parsed_link.netloc.endswith('.' + parsed_target.netloc):
            subdomain_links.append(link)
        elif parsed_link.netloc != parsed_target.netloc:
            external_links.append(link)
        else:
            other_links.append(link)
    
    # Save all links in one file
    all_links_file = "{}/all_links.txt".format(scan_dir)
    with open(all_links_file, 'w', encoding='utf-8') as f:
        f.write("# Zeus Scanner - Blackwidow Crawl Results\n")
        f.write("# Target: {}\n".format(target_url))
        f.write("# Timestamp: {}\n".format(timestamp))
        f.write("# Total Links Found: {}\n".format(len(found_links)))
        f.write("# " + "="*60 + "\n\n")
        for link in found_links:
            f.write(link + "\n")
    
    # Save categorized results
    categories = {
        'internal_links.txt': internal_links,
        'external_links.txt': external_links,
        'subdomain_links.txt': subdomain_links,
        'document_links.txt': document_links,
        'other_links.txt': other_links
    }
    
    for filename, links in categories.items():
        if links:  # Only create file if there are links in this category
            filepath = "{}/{}".format(scan_dir, filename)
            with open(filepath, 'w', encoding='utf-8') as f:
                f.write("# Zeus Scanner - {} Results\n".format(filename.replace('_', ' ').replace('.txt', '').title()))
                f.write("# Target: {}\n".format(target_url))
                f.write("# Count: {}\n".format(len(links)))
                f.write("# " + "="*60 + "\n\n")
                for link in links:
                    f.write(link + "\n")
    
    # Create summary report
    summary_file = "{}/crawl_summary.txt".format(scan_dir)
    with open(summary_file, 'w', encoding='utf-8') as f:
        f.write("Zeus Scanner - Blackwidow Crawl Summary Report\n")
        f.write("="*50 + "\n\n")
        f.write("Target URL: {}\n".format(target_url))
        f.write("Scan Timestamp: {}\n".format(timestamp))
        f.write("Total Links Found: {}\n\n".format(len(found_links)))
        f.write("Link Categories:\n")
        f.write("-" * 20 + "\n")
        f.write("Internal Links: {}\n".format(len(internal_links)))
        f.write("External Links: {}\n".format(len(external_links)))
        f.write("Subdomain Links: {}\n".format(len(subdomain_links)))
        f.write("Document Links: {}\n".format(len(document_links)))
        f.write("Other Links: {}\n\n".format(len(other_links)))
        
        if document_links:
            f.write("Document Files Found:\n")
            f.write("-" * 20 + "\n")
            for doc in document_links:
                f.write("- {}\n".format(doc))
            f.write("\n")
        
        f.write("Files Generated:\n")
        f.write("-" * 15 + "\n")
        f.write("- all_links.txt (All discovered URLs)\n")
        if internal_links:
            f.write("- internal_links.txt (Same domain URLs)\n")
        if external_links:
            f.write("- external_links.txt (External domain URLs)\n")
        if subdomain_links:
            f.write("- subdomain_links.txt (Subdomain URLs)\n")
        if document_links:
            f.write("- document_links.txt (Document files)\n")
        if other_links:
            f.write("- other_links.txt (Miscellaneous URLs)\n")
    
    # Display save confirmation with colors
    print(f"\n{Fore.GREEN}Results saved to: {scan_dir}{Style.RESET_ALL}")
    print(f"{Fore.BLUE}Files created:{Style.RESET_ALL}")
    print(f"   all_links.txt ({len(found_links)} URLs)")
    if internal_links:
        print(f"   internal_links.txt ({len(internal_links)} URLs)")
    if external_links:
        print(f"   external_links.txt ({len(external_links)} URLs)")
    if subdomain_links:
        print(f"   subdomain_links.txt ({len(subdomain_links)} URLs)")
    if document_links:
        print(f"   document_links.txt ({len(document_links)} files)")
    if other_links:
        print(f"   other_links.txt ({len(other_links)} URLs)")
    print(f"   crawl_summary.txt (Detailed report)")
    print(f"{Fore.YELLOW}{'='*60}{Style.RESET_ALL}\n")