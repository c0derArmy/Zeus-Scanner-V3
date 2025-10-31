"""
Enhanced Color Utilities for Zeus Scanner
Provides advanced colorful output capabilities for all attack modules
"""

import lib.core.settings

class Colors:
    """Enhanced color utilities for Zeus Scanner"""
    
    # ANSI Color Codes
    RESET = "\033[0m"
    BOLD = "\033[1m"
    DIM = "\033[2m"
    UNDERLINE = "\033[4m"
    BLINK = "\033[5m"
    REVERSE = "\033[7m"
    
    # Foreground Colors
    BLACK = "\033[30m"
    RED = "\033[31m"
    GREEN = "\033[32m"
    YELLOW = "\033[33m"
    BLUE = "\033[34m"
    MAGENTA = "\033[35m"
    CYAN = "\033[36m"
    WHITE = "\033[37m"
    
    # Bright Foreground Colors
    BRIGHT_BLACK = "\033[90m"
    BRIGHT_RED = "\033[91m"
    BRIGHT_GREEN = "\033[92m"
    BRIGHT_YELLOW = "\033[93m"
    BRIGHT_BLUE = "\033[94m"
    BRIGHT_MAGENTA = "\033[95m"
    BRIGHT_CYAN = "\033[96m"
    BRIGHT_WHITE = "\033[97m"
    
    # Background Colors
    BG_BLACK = "\033[40m"
    BG_RED = "\033[41m"
    BG_GREEN = "\033[42m"
    BG_YELLOW = "\033[43m"
    BG_BLUE = "\033[44m"
    BG_MAGENTA = "\033[45m"
    BG_CYAN = "\033[46m"
    BG_WHITE = "\033[47m"

def colorful_banner(text, style="success"):
    """Create colorful banners for different attack types"""
    styles = {
        "success": (Colors.BRIGHT_GREEN, "✓"),
        "error": (Colors.BRIGHT_RED, "✗"),
        "warning": (Colors.BRIGHT_YELLOW, "⚠"),
        "info": (Colors.BRIGHT_CYAN, "ℹ"),
        "attack": (Colors.BRIGHT_MAGENTA),
        "vulnerability": (Colors.RED + Colors.BG_YELLOW)
    }
    
    color, symbol = styles.get(style, (Colors.WHITE, "•"))
    
    border = "=" * (len(text) + 10)
    return f"{color}{Colors.BOLD}{border}\n     {symbol} {text} {symbol}\n{border}{Colors.RESET}"

def attack_progress(current, total, attack_type="SCAN"):
    """Show colorful attack progress"""
    percentage = (current / total) * 100
    bar_length = 40
    filled_length = int(bar_length * current // total)
    
    # Color based on progress
    if percentage < 25:
        color = Colors.BRIGHT_BLUE
    elif percentage < 50:
        color = Colors.BRIGHT_CYAN
    elif percentage < 75:
        color = Colors.BRIGHT_YELLOW
    else:
        color = Colors.BRIGHT_GREEN
    
    bar = "█" * filled_length + "░" * (bar_length - filled_length)
    
    return (f"{color}[{attack_type}] "
            f"[{bar}] "
            f"{percentage:5.1f}% "
            f"({current}/{total}){Colors.RESET}")

def vulnerability_alert(vuln_type, payload, url, severity="HIGH"):
    """Create dramatic vulnerability alerts"""
    severity_colors = {
        "CRITICAL": Colors.RED + Colors.BG_WHITE + Colors.BOLD,
        "HIGH": Colors.BRIGHT_RED + Colors.BOLD,
        "MEDIUM": Colors.BRIGHT_YELLOW + Colors.BOLD,
        "LOW": Colors.BRIGHT_BLUE + Colors.BOLD
    }
    
    color = severity_colors.get(severity, Colors.BRIGHT_RED)
    
    alert = f"""
{color}{"▓" * 80}
▓{" " * 78}▓
▓{f"         {vuln_type} VULNERABILITY DETECTED!".center(78)}▓
▓{" " * 78}▓
{"▓" * 80}{Colors.RESET}

{Colors.BRIGHT_RED}PAYLOAD:{Colors.RESET} {Colors.YELLOW}{payload}{Colors.RESET}
{Colors.BRIGHT_RED}URL:{Colors.RESET} {Colors.CYAN}{url}{Colors.RESET}
{Colors.BRIGHT_RED}SEVERITY:{Colors.RESET} {color}{severity}{Colors.RESET}
{Colors.BRIGHT_RED}IMPACT:{Colors.RESET} {Colors.BRIGHT_YELLOW}Code execution possible{Colors.RESET}

{color}{"▓" * 80}{Colors.RESET}
"""
    return alert

def status_message(message, status="info"):
    """Create colorful status messages"""
    status_config = {
        "success": (Colors.BRIGHT_GREEN, "SUCCESS", "✓"),
        "error": (Colors.BRIGHT_RED, "ERROR", "✗"),
        "warning": (Colors.BRIGHT_YELLOW, "WARNING", "⚠"),
        "info": (Colors.BRIGHT_CYAN, "INFO", "ℹ"),
        "scanning": (Colors.BRIGHT_MAGENTA, "SCANNING"),
        "found": (Colors.GREEN + Colors.BG_BLACK, "FOUND")
    }
    
    color, status_text, symbol = status_config.get(status, (Colors.WHITE, "MESSAGE", "•"))
    
    return f"{color}[{status_text}]{Colors.RESET} {symbol} {message}"

def port_status_color(status):
    """Color code port statuses"""
    status_colors = {
        "open": Colors.BRIGHT_RED + Colors.BOLD,
        "closed": Colors.BRIGHT_GREEN,
        "filtered": Colors.BRIGHT_YELLOW,
        "unknown": Colors.BRIGHT_BLUE
    }
    
    color = status_colors.get(status.lower(), Colors.WHITE)
    return f"{color}{status.upper()}{Colors.RESET}"

def sqlmap_message_color(message, level):
    """Color SQLMap messages based on content and level"""
    message_lower = message.lower()
    
    # Critical vulnerability indicators
    if any(keyword in message_lower for keyword in ["vulnerable", "injection found", "exploitable"]):
        return Colors.BRIGHT_RED + Colors.BOLD + message + Colors.RESET
    
    # Parameter testing indicators  
    elif any(keyword in message_lower for keyword in ["testing parameter", "checking", "payload"]):
        return Colors.BRIGHT_YELLOW + message + Colors.RESET
    
    # Information messages
    elif any(keyword in message_lower for keyword in ["target url", "testing", "scanning"]):
        return Colors.BRIGHT_CYAN + message + Colors.RESET
    
    # Level-based coloring
    elif level == "ERROR":
        return Colors.BRIGHT_RED + message + Colors.RESET
    elif level == "WARNING":
        return Colors.BRIGHT_YELLOW + message + Colors.RESET
    elif level == "INFO":
        return Colors.BRIGHT_GREEN + message + Colors.RESET
    else:
        return Colors.WHITE + message + Colors.RESET

def create_table(headers, rows, title="SCAN RESULTS"):
    """Create colorful ASCII tables"""
    # Calculate column widths
    col_widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in rows:
            if i < len(row):
                max_width = max(max_width, len(str(row[i])))
        col_widths.append(max_width + 2)
    
    total_width = sum(col_widths) + len(headers) + 1
    
    # Create table
    table = f"{Colors.BRIGHT_CYAN}{'═' * total_width}\n"
    table += f"║{title.center(total_width - 2)}║\n"
    table += f"{'═' * total_width}\n"
    
    # Headers
    header_row = "║"
    for i, header in enumerate(headers):
        header_row += f"{Colors.BRIGHT_YELLOW}{header.ljust(col_widths[i])}{Colors.BRIGHT_CYAN}║"
    table += header_row + "\n"
    
    table += f"{'═' * total_width}\n"
    
    # Data rows
    for row in rows:
        data_row = "║"
        for i, cell in enumerate(row):
            if i < len(col_widths):
                cell_str = str(cell).ljust(col_widths[i])
                if i == 0:  # First column (usually status) gets special coloring
                    if "vulnerable" in str(cell).lower() or "open" in str(cell).lower():
                        cell_str = f"{Colors.BRIGHT_RED}{cell_str}{Colors.BRIGHT_CYAN}"
                    elif "secure" in str(cell).lower() or "closed" in str(cell).lower():
                        cell_str = f"{Colors.BRIGHT_GREEN}{cell_str}{Colors.BRIGHT_CYAN}"
                    else:
                        cell_str = f"{Colors.WHITE}{cell_str}{Colors.BRIGHT_CYAN}"
                else:
                    cell_str = f"{Colors.WHITE}{cell_str}{Colors.BRIGHT_CYAN}"
                data_row += cell_str + "║"
        table += data_row + "\n"
    
    table += f"{'═' * total_width}{Colors.RESET}\n"
    
    return table

# Convenience functions using existing Zeus color system
def zeus_color(text, level):
    """Use Zeus Scanner's existing color system"""
    return lib.core.settings.set_color(text, level=level)

def success(text):
    """Green success message"""
    return zeus_color(text, 25)

def error(text):
    """Red error message"""
    return zeus_color(text, 40)

def warning(text):
    """Yellow warning message"""  
    return zeus_color(text, 30)

def info(text):
    """Cyan info message"""
    return zeus_color(text, 15)

def highlight(text):
    """Bright highlight message"""
    return zeus_color(text, 35)
