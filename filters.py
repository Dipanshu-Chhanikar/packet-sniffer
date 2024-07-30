FILTERS = {
    "HTTP": "tcp port 80",
    "HTTPS": "tcp port 443",
    "SMTP": "tcp port 25",
    "TCP": "tcp",
    "UDP": "udp",
    "IP": "ip",
    "FTP": "tcp port 21",
}

def get_filter_string(option):
    return FILTERS.get(option, "")
