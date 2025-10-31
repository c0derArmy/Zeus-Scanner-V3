import os
import re
import time
import importlib
import unicodedata

from xml.dom import minidom
from requests.exceptions import (
    ConnectionError,
    ReadTimeout
)

from var.auto_issue.github import request_issue_creation
from lib.core.common import (
    write_to_log_file,
    shutdown,
    pause,
    get_page,
    HTTP_HEADER,
)
from lib.core.settings import (
    logger, set_color,
    HEADER_XML_DATA,
    replace_http,
    HEADER_RESULT_PATH,
    COOKIE_LOG_PATH,
    ISSUE_LINK,
    DBMS_ERRORS,
    UNKNOWN_FIREWALL_FINGERPRINT_PATH,
    UNKNOWN_FIREWALL_FILENAME,
    COOKIE_FILENAME,
    HEADERS_FILENAME,
    SQLI_FOUND_FILENAME,
    SQLI_SITES_FILEPATH,
    DETECT_PLUGINS_PATH
)
from lib.core.wafw00f_integration import detect_waf_with_wafw00f


def get_charset(html, headers, **kwargs):
    """
    detect the target URL charset
    """
    charset_regex = re.compile(r'charset=[\"]?([a-zA-Z0-9_-]+)', re.I)
    
    # Handle both string and bytes input
    if isinstance(html, bytes):
        html = html.decode('utf-8', errors='ignore')
    
    charset = charset_regex.search(html)
    if charset is not None:
        return charset.group(1)
    else:
        content = headers.get(HTTP_HEADER.CONTENT_TYPE, "")
        charset = charset_regex.search(content)
        if charset is not None:
            return charset.group(1)
    return None


def detect_plugins(html, headers, **kwargs):
    verbose = kwargs.get("verbose", False)

    try:
        retval = []
        plugin_skip_schema = ("__init__", ".pyc")
        plugin_file_list = [f for f in os.listdir(DETECT_PLUGINS_PATH) if not any(s in f for s in plugin_skip_schema)]
        for plugin in plugin_file_list:
            plugin = plugin[:-3]
            if verbose:
                logger.debug(set_color(
                    "loading script '{}'".format(plugin), level=10
                ))
            plugin_detection = "lib.plugins.{}"
            plugin_detection = plugin_detection.format(plugin)
            plugin_detection = importlib.import_module(plugin_detection)
            if plugin_detection.search(html, headers=headers) is True:
                retval.append((plugin_detection.__product__, plugin_detection.__description__))
        if len(retval) > 0:
            return retval
        return None
    except Exception as e:
        logger.exception(str(e))
        if "Read timed out." or "Connection reset by peer" in str(e):
            logger.warning(set_color(
                "plugin request failed, assuming no plugins and continuing", level=30
            ))
            return None
        else:
            logger.exception(set_color(
                "plugin detection has failed with error {}".format(str(e))
            ))
            request_issue_creation()


def load_xml_data(path, start_node="header", search_node="name"):
    """
    load the XML data
    """
    retval = []
    fetched_xml = minidom.parse(path)
    item_list = fetched_xml.getElementsByTagName(start_node)
    for value in item_list:
        retval.append(value.attributes[search_node].value)
    return retval


def load_headers(url, req, **kwargs):
    """
    load the HTTP headers
    """
    literal_match = re.compile(r"\\(\X(\d+)?\w+)?", re.I)

    if len(req.cookies) > 0:
        logger.info(set_color(
            "found a request cookie, saving to file", level=25
        ))
        try:
            cookie_start = req.cookies.keys()
            cookie_value = req.cookies.values()
            write_to_log_file(
                "{}={}".format(''.join(cookie_start), ''.join(cookie_value)),
                COOKIE_LOG_PATH, COOKIE_FILENAME.format(replace_http(url))
            )
        except Exception:
            write_to_log_file(
                [c for c in req.cookies.itervalues()], COOKIE_LOG_PATH,
                COOKIE_FILENAME.format(replace_http(url))
            )
    retval = {}
    do_not_use = []
    http_headers = req.headers
    for header in http_headers:
        try:
            # check for Unicode in the string, this is just a safety net in case something is missed
            # chances are nothing will be matched
            if literal_match.search(header) is not None:
                retval[header] = unicodedata.normalize(
                    "NFKD", u"{}".format(http_headers[header])
                ).encode("ascii", errors="ignore")
            else:
                # test to see if there are any unicode errors in the string
                retval[header] = unicodedata.normalize(
                    "NFKD", u"{}".format(http_headers[header])
                ).encode("ascii", errors="ignore")
        # just to be safe, we're going to put all the possible Unicode errors into a tuple
        except (UnicodeEncodeError, UnicodeDecodeError, UnicodeError, UnicodeTranslateError, UnicodeWarning):
            # if there are any errors, we're going to append them to a `do_not_use` list
            do_not_use.append(header)
    # clear the dict so we can re-add to it
    retval.clear()
    for head in http_headers:
        # if the header is in the list, we skip it
        if head not in do_not_use:
            retval[head] = http_headers[head]
    # return a dict of safe unicodeless HTTP headers
    return retval


def compare_headers(found_headers, comparable_headers):
    """
    compare the headers against one another
    """
    retval = set()
    for header in comparable_headers:
        if header in found_headers:
            retval.add(header)
    return retval


def main_header_check(url, **kwargs):
    """
    main function
    """
    verbose = kwargs.get("verbose", False)
    agent = kwargs.get("agent", None)
    proxy = kwargs.get("proxy", None)
    xforward = kwargs.get("xforward", False)
    identify_waf = kwargs.get("identify_waf", True)
    identify_plugins = kwargs.get("identify_plugins", True)
    show_description = kwargs.get("show_description", False)
    attempts = kwargs.get("attempts", 3)

    default_sleep_time = 5
    protection = {"hostname": url}
    definition = {
        "x-xss": ("protection against XSS attacks", "XSS"),
        "strict-transport": ("protection against unencrypted connections (force HTTPS connection)", "HTTPS"),
        "x-frame": ("protection against clickjacking vulnerabilities", "CLICKJACKING"),
        "x-content": ("protection against MIME type attacks", "MIME"),
        "x-csrf": ("protection against Cross-Site Forgery attacks", "CSRF"),
        "x-xsrf": ("protection against Cross-Site Forgery attacks", "CSRF"),
        "public-key": ("protection to reduce success rates of MITM attacks", "MITM"),
        "content-security": ("header protection against multiple attack types", "ALL")
    }

    try:
        req, status, html, headers = get_page(url, proxy=proxy, agent=agent, xforward=xforward)

        logger.info(set_color(
            "detecting target charset"
        ))
        charset = get_charset(html, headers)
        if charset is not None:
            logger.info(set_color(
                "target charset appears to be '{}'".format(charset), level=25
            ))
        else:
            logger.warning(set_color(
                "unable to detect target charset", level=30
            ))
        if identify_waf:
            logger.info(set_color(
                "checking if target URL is protected by some kind of WAF/IPS/IDS using wafw00f"
            ))
            
            identified_waf = detect_waf_with_wafw00f(url, verbose=verbose, proxy=proxy)

            if identified_waf is None:
                logger.info(set_color(
                    "no WAF/IDS/IPS has been identified on target URL", level=25
                ))
            else:
                logger.warning(set_color(
                    "the target URL WAF/IDS/IPS has been identified as '{}'".format(identified_waf), level=35
                ))

        if identify_plugins:
            logger.info(set_color(
                "attempting to identify plugins"
            ))
            identified_plugin = detect_plugins(html, headers, verbose=verbose)
            if identified_plugin is not None:
                for plugin in identified_plugin:
                    if show_description:
                        logger.info(set_color(
                            "possible plugin identified as '{}' (description: '{}')".format(
                                plugin[0], plugin[1]
                            ), level=25
                        ))
                    else:
                        logger.info(set_color(
                            "possible plugin identified as '{}'".format(
                                plugin[0]
                            ), level=25
                        ))
            else:
                logger.warning(set_color(
                    "no known plugins identified on target", level=30
                ))

        if verbose:
            logger.debug(set_color(
                "loading XML data", level=10
            ))
        comparable_headers = load_xml_data(HEADER_XML_DATA)
        logger.info(set_color(
            "attempting to get request headers for '{}'".format(url.strip())
        ))
        try:
            found_headers = load_headers(url, req)
        except (ConnectionError, Exception) as e:
            if "Read timed out." or "Connection reset by peer" in str(e):
                found_headers = None
            else:
                logger.exception(set_color(
                    "Zeus has hit an unexpected error and cannot continue '{}'".format(e), level=50
                ))
                request_issue_creation()

        if found_headers is not None:
            if verbose:
                logger.debug(set_color(
                    "fetched {}".format(found_headers), level=10
                ))
            headers_established = [str(h) for h in compare_headers(found_headers, comparable_headers)]
            for key in definition.iterkeys():
                if any(key in h.lower() for h in headers_established):
                    logger.warning(set_color(
                        "provided target has {}".format(definition[key][0]), level=30
                    ))
            for key in found_headers.iterkeys():
                protection[key] = found_headers[key]
            logger.info(set_color(
                "writing found headers to log file", level=25
            ))
            return write_to_log_file(protection, HEADER_RESULT_PATH, HEADERS_FILENAME.format(replace_http(url)))
        else:
            logger.error(set_color(
                "unable to retrieve headers for site '{}'".format(url.strip()), level=40
            ))
    except ConnectionError:
        attempts = attempts - 1
        if attempts == 0:
            return False
        logger.warning(set_color(
            "target actively refused the connection, sleeping for {}s and retrying the request".format(
                default_sleep_time
            ), level=30
        ))
        time.sleep(default_sleep_time)
        main_header_check(
            url, proxy=proxy, agent=agent, xforward=xforward, show_description=show_description,
            identify_plugins=identify_plugins, identify_waf=identify_waf, verbose=verbose,
            attempts=attempts
        )
    except ReadTimeout:
        logger.error(set_color(
            "meta-data retrieval failed due to target URL timing out, skipping", level=40
        ))
    except KeyboardInterrupt:
        if not pause():
            shutdown()
    except Exception as e:
        logger.exception(set_color(
            "meta-data retrieval failed with unexpected error '{}'".format(
                str(e)
            ), level=50
        ))