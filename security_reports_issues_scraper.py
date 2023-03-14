# Standard Python libraries
import csv
import configparser
import json
import logging
import requests
import time
import os.path

# Custom Library
from github3 import login

"""
Read csv file 
entitled 'Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv'
"""
def log4shell_read_csv_report(file_name):
    log4shell_list_issues = []
    with open(file_name, 'r') as file:
        # read the report
        csv_reader = csv.reader(file)
        # display the contents of the CSV file
        for row in csv_reader:
            log4shell_list_issues.append(row)
            # print(row)
    return log4shell_list_issues

"""
Read csv file
entitled 'Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv'
"""

def weekly_nal_read_csv_report(file_name):
    weekly_nal_list_issues = []
    with open(file_name, 'r') as file:
        # read the report
        csv_reader = csv.reader(file)
        # display the contents of the CSV file
        for row in csv_reader:
            weekly_nal_list_issues.append(row)
    return weekly_nal_list_issues

"""
Read csv file
entitled 'ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan Report.csv'
"""
def ars_bod_read_csv_report(file_name):
    ars_bod_list_issues = []
    with open(file_name, 'r') as file:
        # read the report
        csv_reader = csv.reader(file)
        # display the contents of the CSV file
        for row in csv_reader:
            ars_bod_list_issues.append(row)
            print(row)
    return ars_bod_list_issues

# Verify if more than one of the same issue appears in security report .csv file
def verify_duplicates(list):
    # no_dup_unique_ids_list = []
    duplicates_count = 0
    print("\nVerify if duplicates occur in unique identifiers' list")
    for uniq_id in list:
        if list.count(uniq_id) > 1:
            print("Duplicate ids are present in this list")
            duplicates_count += 1
            list.pop(uniq_id)
        else:
            print("No duplicates")
    print("Total number of duplicates: ", duplicates_count)
    return list

def log4shell_create_unique_ids(list):
    print("\nUnique IDs (Log4shell): ")
    print("Length of Log4Shell list: ", len(list))
    log4shell_unique_ids_list = []
    assigned_unique_ids_list = []
    for row in range(len(list)):
        '''
        unique_id created using unique fields from 5 columns assigned to each issue in Log4Shell report:
        list[row][0] -> Column: "Plugin"
        list[row][1] -> Column: "Plugin Name"
        list[row][3] -> Column: "IP Address"
        list[row][4] -> Column: "Port Number"
        list[row][11] -> Column: "First Discovered"
        '''

        unique_id = str(list[row][0]) + unique_id_title_delimiter + list[row][1] + unique_id_title_delimiter + str(
            list[row][3]) + unique_id_title_delimiter + str(list[row][4]) + unique_id_title_delimiter + list[row][11]

        print(unique_id, list[row])
        assigned_pair_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(assigned_pair_unique_id)
    return assigned_unique_ids_list

def weekly_nal_create_unique_ids(list):
    print("\nUnique IDs: ")
    print("Length of list: ", len(list))
    weekly_nal_unique_ids_list = []
    assigned_unique_ids_list = []
    for row in range(len(list)):
        '''
        unique_id created using 5 unique columns assigned to each issue in Weekly NAL:
        list[row][0] -> Column: "Plugin"
        list[row][1] -> Column: "Plugin Name"
        list[row][3] -> Column: "IP Address"
        list[row][4] -> Column: "Port Number"
        list[row][12] -> Column: "First Discovered"
        '''
        # unique_id_delimiter = gitconfig["title"]["delimiter"]
        unique_id = str(list[row][0]) + unique_id_title_delimiter + list[row][1] + unique_id_title_delimiter + str(
            list[row][3]) + unique_id_title_delimiter + str(list[row][4]) + unique_id_title_delimiter + list[row][11]

        weekly_nal_unique_ids_list.append(unique_id)

        pair_assigned_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(pair_assigned_unique_id)
    print("list of assigned unique ids:")
    print(assigned_unique_ids_list)
    return assigned_unique_ids_list

def ars_bod_create_unique_ids(list):
    print("\nUnique IDs: ")
    print("Length of list: ", len(list))
    ARS_BOD_unique_ids_list = []
    assigned_unique_ids_list = []
    for row in range(len(list)):
        '''
        unique_id created using 5 unique columns assigned to each issue in ARS BOD:
        list[row][0] -> Column: "Plugin"
        list[row][1] -> Column: "Plugin Name"
        list[row][4] -> Column: "IP Address"
        list[row][5] -> Column: "Port Number"
        list[row][18] -> Column: "First Discovered"
        '''
        unique_id = str(list[row][0]) + unique_id_title_delimiter + list[row][1] + unique_id_title_delimiter + str(
            list[row][3]) + unique_id_title_delimiter + str(list[row][4]) + unique_id_title_delimiter + list[row][18]

        pair_assigned_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(pair_assigned_unique_id)
    return assigned_unique_ids_list

def log4shell_create_github_issue(title, labels=None, assignees=None, body=None):
    # Create an issue on github.com using the given parameters.
    # Our url to create issues via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (owner, repo)
    # Create an authenticated session to create the issue in security report
    session = requests.Session()
    session.auth = (owner, personal_access_token)

    '''
    response = session.get(url=url, timeout = 0.001)
    print("response.text: ")
    print(response.text)
    print("\nResponse header: ")
    print(response.headers)
    '''

    # for unique_id in Security_Report:
    # Create new issue
    log4shell_issue = {
        'title': title,  # assign each new issue to title
        'labels': labels,
        'assignees': assignees,
        'body':
            f'''
### Plugin: {unique_ids_list[0]}
### Plugin Name: {unique_ids_list[1]}
### Severity: {unique_ids_list[2]}
### IP Address: {unique_ids_list[3]}
### Port: {unique_ids_list[4]}
### DNS Name: {unique_ids_list[5]}
### NetBios Name: {unique_ids_list[6]}
### Plugin Output: {unique_ids_list[7]}
### Solution: {unique_ids_list[8]}
### CVSS V3 Base Score: {unique_ids_list[9]}
### CVE: {unique_ids_list[10]}
### First Discovered: {unique_ids_list[11]}
### Last Observed: {unique_ids_list[12]}
'''
    }

    # Add the issue to our repository
    new_repo = session.post(url, json.dumps(log4shell_issue))
    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))

        """
        Testing:
        
        logging.DEBUG(str('Successfully Created Issue {0:s}'.format(title)))
        logging.DEBUG(print('Successfully Created Issue {0:s}'.format(title)))
        
        id_values = 'Successfully Created Issue {0:s}'.format(title))
        logging.DEBUG('id_values')
        """
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)
        """
        logging.DEBUG(print('Could not create Issue {0:s}'.format(title)))
        logging.DEBUG(print('Response: ', new_repo.content))
        
        logging.DEBUG(Could not create Issue {0:s}'.format(title))
        logging.DEBUG(Response: ', new_repo.content)
        """
def weekly_nal_create_github_issue(title, labels=None, assignees=None, body=None):
    # Create an issue on github.com using the given parameters.
    # Our url to create issues via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (owner, repo)
    # Create an authenticated session to create the issue
    session = requests.Session()
    session.auth = (owner, personal_access_token)

    # Create new issues for Weekly NAL Report
    weekly_nal_issue = {
        'title': title,  # assign each new issue to title
        'labels': labels,
        'assignees': assignees,
        'body':
            f'''             
### Plugin: {unique_ids_list[0]}
### Plugin Name: {unique_ids_list[1]}
### Severity: {unique_ids_list[2]}
### IP Address: {unique_ids_list[3]}
### Port: {unique_ids_list[4]}
### DNS Name: {unique_ids_list[5]}
### NetBios Name: {unique_ids_list[6]}
### Plugin Output: {unique_ids_list[7]}
### Solution: {unique_ids_list[8]}
### CVSS V3 Base Score: {unique_ids_list[9]}
### CVE: {unique_ids_list[10]}
### First Discovered: {unique_ids_list[11]}
### Last Observed: {unique_ids_list[12]}
'''
    }
    # Add the issue to our repository
    new_repo = session.post(url, json.dumps(weekly_nal_issue))
    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)

def ars_bod_create_github_issue(title, labels=None, assignees=None, body=None):
    # Create an issue on github.com using the given parameters.
    # Our url to create issues via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (owner, repo)
    # Create an authenticated session to create the issue
    session = requests.Session()
    session.auth = (owner, personal_access_token)

    # Create new issues for Weekly NAL Security Report
    ars_bod_issue = {
        'title': title,  # assign each new issue to title
        'labels': labels,
        'assignees': assignees,
        'body':
            f'''             
### Plugin: {unique_ids_list[0]}
### Plugin Name: {unique_ids_list[1]}
### Family: {unique_ids_list[2]}
### Severity: {unique_ids_list[3]}
### IP Address: {unique_ids_list[4]}
### Port: {unique_ids_list[5]}
### MAC Address: {unique_ids_list[6]}
### DNS Name: {unique_ids_list[7]}
### NetBios Name: {unique_ids_list[8]}
### Plugin Output: {unique_ids_list[9]}
### Synopsis: {unique_ids_list[10]}
### Description: {unique_ids_list[11]}
### Solution: {unique_ids_list[12]}
### Vulnerability Priority Rating: {unique_ids_list[13]}
### CVSS V2 Base Score: {unique_ids_list[14]}
### CVSS V3 Base Score: {unique_ids_list[15]}
### CPE: {unique_ids_list[16]}
### CVE: {unique_ids_list[17]}
### First Discovered: {unique_ids_list[18]}
### Last Observed: {unique_ids_list[19]}
### Cross References: {unique_ids_list[20]}
'''
    }
    # Add the issue to our repository
    new_repo = session.post(url, json.dumps(ars_bod_issue))
    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)

# Remove header (1st row) of each report
def remove_header(list):
    list.pop(0)
    return list

def create_sets(list):
    list.split()
    for i in list.split():
        print(i)

def delay_api_requests():
    delay_in_sec = int(config['API']['delay'])
    time.sleep(delay_in_sec)

 # Initializing Basic Configuration File
    logging.basicConfig(filename="security_reports_issues_scraper_202302.log", encoding="utf-8", level=logging.DEBUG,
                        format="%(asctime)s %(levelname)s %(message)s", datefmt="%m/%d/%Y %H:%M:%S")

# ConfigParser Object
config = configparser.ConfigParser()

# Read "gitconfig.ini"
config.read("gitconfig.ini")

# Read config.sections()
config.sections()

# Read owner of [user] from config.ini
owner = config["user"]["owner"]

# Read repo of [user] from config.ini
repo = config["user"]["repo"]

# Read personal_access_token within [API] in config.ini
personal_access_token = config["API"]["personal_access_token"]

unique_id_title_delimiter = config["unique-id-title"]["delimiter"]

"""
print(owner)
print(repo)
print(personal_access_token)
"""

# Create hash object from "gitconfig.ini" configuration file
# to read in weekly security report related to "Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report
# - CHML Vulns  7 Days.csv"
log4shell_report = config['security-csv-reports']['Log4Shell_report']

# Create hash object from "gitconfig.ini" configuration file
# to read in weekly csv security reports related to "Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML
# Vulns  7 Days.csv"
weekly_nal_report = config['security-csv-reports']['Weekly_NAL_report']

# Create hash object from "gitconfig.ini" configuration file
# to read in weekly csv reports related to "ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan
# Report.csv"
ars_bod_report = config['security-csv-reports']['ARS_BOD_report']

github = login(owner, personal_access_token)

try:
    # Starting security_reports_issues_scraper.py
    logging.info("Successfully started execution of <security_reports_issues_scraper.py>")
    # Enter Github Login Credential
    logging.info("Logging into repo <isdapps/IT-Security-Test> on github.")
    """
    if github == login(owner, personal_access_token):
        logging.info("Successfully logged into repo <isdapps/IT-Security-Test>.")
    else:
        logging.error("Unable to log into repo <isdapps/IT-Security-Test> using current login credentials.")
    """
    logging.info("Connecting into https://api.github.com.")
    
    """
    logging.info("Logging into repo <isdapps/IT-Security-Test> on github.")
    logging.info("Successfully logged into repo <isdapps/IT-Security-Test>")
    logging.info("Successfully Connect to API")
    logging.info("Create issue")
    logging.info("Initialize issue")
    """
    logging.info(
        "Processing <Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> to create issues.")
    print("Log4Shell report:")
    logging.info(
        "Checking if <Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> exists.")
    #if os.path.exists(log4shell_report):

    # / path
    # Testing to use path variables
    # Testing Windows path: \
    # Testing path on linux: /

    log4shell_issues_list = []
    log4shell_issues_list = log4shell_read_csv_report(log4shell_report)

    '''
    # Create Log4Shell header to security reports headers
    log4shell_header = log4shell_issues_list.pop(0)
    '''

    log4shell_no_header_issues_list = remove_header(log4shell_issues_list)
    print("No header list: ", log4shell_no_header_issues_list)
    # print all issues of Log4Shell security report without header
    print("\n(No header)Total Amount of Log4Shell issues:", len(log4shell_no_header_issues_list))

    for issue in range(len(log4shell_no_header_issues_list)):
        print(log4shell_no_header_issues_list[issue])
        # all_unique_ids_list.append(Log4Shell_list_issues[i])

    #verify_duplicates(log4shell_no_header_issues_list)
    #log4shell_all_issues_list = log4shell_create_unique_ids(log4shell_no_header_issues_list)
    """
    log4shell_no_dupl_all_issues_list = verify_duplicates(log4shell_no_header_issues_list)
    print("log4shell_no_dupl_all_issues_list:")
    print(log4shell_no_dupl_all_issues_list)
    """

    # verify duplicates in Log4Shell report
    log4shell_no_dupl_all_issues_list = verify_duplicates(log4shell_no_header_issues_list)
    print("log4shell_no_dupl_all_issues_list: ")
    print(log4shell_no_dupl_all_issues_list)
    # log4shell_create_unique_ids
    log4shell_no_dupl_all_issues_list = log4shell_create_unique_ids(log4shell_no_dupl_all_issues_list)
    # Iterate through unique identifiers (no duplicates) to pass each issue
    # into Log4Shell_create_github_issue() function
    print("\nCreate issues from Log4Shell Report: ")

    for issue in range(len(log4shell_no_dupl_all_issues_list)):
        print("Issue in log4shell_no_dupl_all_issues_list")
        print(issue)
        unique_id = log4shell_no_dupl_all_issues_list[issue][0]
        print("Unique_id")
        print(unique_id)
        print("unique_ids_list")
        unique_ids_list = log4shell_no_dupl_all_issues_list[issue][1]
        print(unique_ids_list)

        print("&*Test")
        #verify_duplicates(unique_ids_list)

        # Call "delay_api_requests()" function to execute delay_in_sec initialized in gitconfig.ini
        delay_api_requests()

        # Create each issue on github from Log4Shell
        log4shell_create_github_issue(unique_id, ["Test Label"], ['brian-mustafa'], unique_ids_list)

    print("\nWeekly NAL Report:")
    logging.info(
        "Processing <Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> report to create issues.")
    weekly_nal_issues_list = []
    weekly_nal_issues_list = weekly_nal_read_csv_report(weekly_nal_report)
    logging.info(
        "Checking if <Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> report exists.")
    logging.error(
        "<Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> does not exist.")
    '''
    weekly_nal_header = weekly_nal_issues_list.pop(0)
    '''
    weekly_nal_no_header_issues_list = remove_header(weekly_nal_issues_list)
    print("(No header)Length of Weekly NAL list_issues:", len(weekly_nal_no_header_issues_list))
    print("(No header) List of Weekly NAL reports' issues:")

    for issue in range(len(weekly_nal_no_header_issues_list)):
        print(weekly_nal_no_header_issues_list[issue])
        # all_unique_ids_list.append(Weekly_NAL_issues_list[j])
        # unique_ids_list.append(Log4Shell_list_issues[row])

    # verify duplicates in Weekly NAL reports
    weekly_nal_no_dupl_all_issues_list = verify_duplicates(weekly_nal_no_header_issues_list)
    print("weekly_nal_no_dupl_all_issues_list")
    print(weekly_nal_no_dupl_all_issues_list)
    # Weekly_nal_create_unique_ids
    weekly_nal_no_dupl_all_issues_list = weekly_nal_create_unique_ids(weekly_nal_no_dupl_all_issues_list)

    # Iterate through unique identifiers (no duplicates) to pass each issue
    # into Weekly_NAL_create_github_issue() function
    print("\n\nCreate issues from Weekly NAL Report: ")

    for issue in range(len(weekly_nal_no_dupl_all_issues_list)):
        unique_id = weekly_nal_no_dupl_all_issues_list[issue][0]

        unique_ids_list = weekly_nal_no_dupl_all_issues_list[issue][1]

        print("Unique IDs List")
        print(unique_ids_list)
        print(weekly_nal_no_dupl_all_issues_list[issue][1][0])

        delay_api_requests()

        log4shell_create_github_issue(unique_id, ["Test Label"], ['brian-mustafa'], unique_ids_list)

    print("\nARS BOD Report:")
    logging.info(
        "Processing <ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan Report.csv> to create issues.")
    ars_bod_issues_list = []
    ars_bod_issues_list = ars_bod_read_csv_report(ars_bod_report)
    logging.info(
        "Checking if <ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan Report.csv> exists.")
    logging.error("<ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan Report.csv> does not exist.")
    ars_bod_no_header_issues_list = remove_header(ars_bod_issues_list)

    # Verify that each unique identifier for ARS BOD Report is returned
    for issue in range(len(ars_bod_no_header_issues_list)):
        print(ars_bod_issues_list[issue])

    print("(No header)Length of ARS BOD reports' list of issues:", len(ars_bod_no_header_issues_list))
    print("(No header) list of issues (ARS_BOD):")

    """
        # verify duplicates in Log4Shell report
        log4shell_no_dupl_all_issues_list = verify_duplicates(log4shell_no_header_issues_list)
        print("log4shell_no_dupl_all_issues_list: ")
        print(log4shell_no_dupl_all_issues_list)
        # log4shell_create_unique_ids
        log4shell_no_dupl_all_issues_list = log4shell_create_unique_ids(log4shell_no_dupl_all_issues_list)
    """
    # verify duplicates in ARS BOD Report
    ars_bod_no_dupl_all_issues_list = verify_duplicates(ars_bod_no_header_issues_list)
    print("ars_bod_no_dupl_all_issues_list")
    print(ars_bod_no_dupl_all_issues_list)
    # ars_bod_create_unique_ids
    ars_bod_no_dupl_all_issues_list = ars_bod_create_unique_ids(ars_bod_no_dupl_all_issues_list)

    # Iterate through unique identifiers (no duplicates) to pass each issue
    # into ARS_BOD_create_github_issue() function
    print("\nCreate issues from ARS BOD Report: ")

    for issue in range(len(ars_bod_no_dupl_all_issues_list)):
        print("ARS_BOD_no_dupl_all_issues_list[i][0]")
        print(ars_bod_no_dupl_all_issues_list[issue][0])
        unique_id = ars_bod_no_dupl_all_issues_list[issue][0]
        unique_ids_list = ars_bod_no_dupl_all_issues_list[issue][1]

        delay_api_requests()
        ars_bod_create_github_issue(unique_id, ["Test Label"], ['brian-mustafa'], unique_ids_list)
    logging.info('Complete Logging')

except AttributeError:
    print("Attribute Error.")
except EOFError:
    print("EOF Error is raised when the input() function hits the end-of-file condition.")
except FileNotFoundError:
    print("No such file or directory solution.")
    logging.error("File Does Not Exist.")
except IndentationError:
    print("Indentation Error is raised when there is an incorrect indentation.")
except IndexError:
    print("Index Error. Index of a sequences(s) is out of range.")
except KeyboardInterrupt:
    print("Keyboard Interrupt is raised when the user hits the interrupt key")
except NameError:
    print("name {} is no defined.")
    logging.error("name '' is not defined.")
except NotImplementedError:
    print("NotImplementedError is raised by abstract methods.")
except UnboundLocalError:
    print(
        '''Unbound Local Error is raised when a reference is made to a local variable in a function
        or method but no value has been bound to that variable.''')
except UnicodeError:
    print("Unicode Error. Unicode-related encoding or decoding error occurred")
