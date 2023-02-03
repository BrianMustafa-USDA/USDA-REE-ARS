import csv
import configparser
import json
import logging
import requests
import time
from github3 import login

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

print(owner)
print(repo)
print(personal_access_token)

# Github Login Credential
github = login(owner, personal_access_token)

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

def weekly_nal_read_csv_report(file_name):
    weekly_nal_list_issues = []
    with open(file_name, 'r') as file:
        # read the report
        csv_reader = csv.reader(file)
        # display the contents of the CSV file
        for row in csv_reader:
            weekly_nal_list_issues.append(row)
    return weekly_nal_list_issues

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

def log4shell_create_unique_ids(list):
    print("\nUnique IDs: ")
    print("Length of list: ", len(list))
    log4shell_unique_ids_list = []
    assigned_unique_ids_list = []
    for row in range(len(list)):
        '''
        unique_id created using unique fields from 5 columns assigned to each issue in Log4Shell report:
        list[row][0] -> Column: "Plugin"
        list[row][1] -> Column: "Plugin Name"
        list[row][3] -> Column: "IP Address"
        list[row][4] -> Column: "Port Number"
        list[row][12] -> Column: "Last Observed"
        '''

        unique_id = str(list[row][0]) + unique_id_title_delimiter + list[row][1] + unique_id_title_delimiter + str(
            list[row][3]) + unique_id_title_delimiter + str(list[row][4]) + unique_id_title_delimiter + list[row][12]

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
        list[row][12] -> Column: "Last Observed"

        '''
        # unique_id_delimiter = gitconfig["title"]["delimiter"]
        unique_id = str(list[row][0]) + unique_id_title_delimiter + list[row][1] + unique_id_title_delimiter + str(
            list[row][3]) + unique_id_title_delimiter + str(list[row][4]) + unique_id_title_delimiter + list[row][12]
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
        list[row][19] -> Column: "Last Observed"
        '''
        unique_id = str(list[row][0]) + unique_id_title_delimiter + list[row][1] + unique_id_title_delimiter + str(
            list[row][3]) + unique_id_title_delimiter + str(list[row][4]) + unique_id_title_delimiter + list[row][19]

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

def remove_header(list):
    list.pop(0)
    no_header_list = list
    return no_header_list

def create_sets(list):
    list.split()
    for i in list.split():
        print(i)

def delay_api_requests():
    delay_in_sec = int(config['API']['delay'])
    time.sleep(delay_in_sec)

'''
def logging():
    logging.basicConfig(filename='activity.log', encoding='utf-8', level=logging.DEBUG)
'''
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

try:
    logging.basicConfig(filename='activities.log', encoding='utf-8', level=logging.DEBUG)
    logging.debug('Start Logging')
    # all_unique_ids_list = []
    print("Log4Shell report:")
    log4shell_issues_list = []
    log4shell_issues_list = log4shell_read_csv_report(log4shell_report)

    '''
    # Create Log4Shell header to security reports headers
    log4shell_header = log4shell_issues_list.pop(0)
    '''

    log4shell_no_header_issues_list = remove_header(log4shell_issues_list)
    print("No header list: ", log4shell_no_header_issues_list)
    # print all issues of Log4Shell security report without header
    print("\n(No header)Length of Log4Shell List of issues:", len(log4shell_no_header_issues_list))

    for issue in range(len(log4shell_no_header_issues_list)):
        print(log4shell_no_header_issues_list[issue])
        # all_unique_ids_list.append(Log4Shell_list_issues[i])

    verify_duplicates(log4shell_no_header_issues_list)
    log4shell_no_dupl_all_issues_list = log4shell_create_unique_ids(log4shell_no_header_issues_list)

    # Iterate through unique identifiers (no duplicates) to pass each issue
    # into Log4Shell_create_github_issue() function
    print("\nCreate issues from Log4Shell Report: ")

    for issue in range(len(log4shell_no_dupl_all_issues_list)):
        unique_id = log4shell_no_dupl_all_issues_list[issue][0]

        unique_ids_list = log4shell_no_dupl_all_issues_list[issue][1]

        print("&*Test")
        print(unique_ids_list)

        delay_api_requests()
        log4shell_create_github_issue(unique_id, ["Test Label"], ['brian-mustafa'], unique_ids_list)

        """
        Test:
        print("sys.audit: ")
        sys.addaudithook(hook: Callable[[str, tuple]])
        sys.audit(str, *args)
        """
    print("\nWeekly NAL Report:")

    weekly_nal_issues_list = []
    weekly_nal_issues_list = weekly_nal_read_csv_report(weekly_nal_report)

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
    verify_duplicates(weekly_nal_no_header_issues_list)
    # Weekly_NAL_create_unique_ids(Weekly_NAL_issues_list)
    weekly_nal_no_dupl_all_issues_list = weekly_nal_create_unique_ids(weekly_nal_no_header_issues_list)

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

    ars_bod_issues_list = []
    ars_bod_issues_list = ars_bod_read_csv_report(ars_bod_report)

    ars_bod_no_header_issues_list = remove_header(ars_bod_issues_list)

    # Verify that each unique identifier for ARS BOD Report is returned
    for issue in range(len(ars_bod_no_header_issues_list)):
        print(ars_bod_issues_list[issue])

    print("(No header)Length of ARS BOD reports' list of issues:", len(ars_bod_no_header_issues_list))
    print("(No header) list of issues (ARS_BOD):")

    verify_duplicates(ars_bod_no_header_issues_list)
    ars_bod_no_dupl_all_issues_list = ars_bod_create_unique_ids(ars_bod_no_header_issues_list)

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
    logging.debug('Complete Logging')

    open('activities.log', 'w')

except AttributeError:
    print("Attribute Error.")
except EOFError:
    print("EOF Error is raised when the input() function hits the end-of-file condition")
except FileNotFoundError:
    print("No such file or directory solution.")
except IndentationError:
    print("IndentationError is raised when there is an incorrect indentation.")
except IndexError:
    print("Index Error. Index of a sequences(s) is out of range.")
except KeyboardInterrupt:
    print("Keyboard Interrupt is raised when the user hits the interrupt key")
except NotImplementedError:
    print("NotImplementedError is raised by abstract methods.")
except UnboundLocalError:
    print(
        '''Unbound Local Error is raised when a reference is made to a local variable in a function
        or method but no value has been bound to that variable.''')
except UnicodeError:
    print("Unicode Error. Unicode-related encoding or decoding error occurred")
except ZeroDivisionError:
    print("ZeroDivisionError is raised when the second operand of a division or module operation is zero.")
