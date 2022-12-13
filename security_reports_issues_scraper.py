import csv
import configparser
import json
import requests
import time
from github3 import login
from pathlib import Path

# ConfigParser Object
config = configparser.ConfigParser()

# Read "gitconfig.ini"
config.read("gitconfig.ini")

# Read config.sections()
config.sections()

# Read owner of [user] from config.ini
owner = config['user']['owner']

# Read repo of [user] from config.ini
repo = config['user']['repo']

# Read personal_access_token in [API] in config.ini

personal_access_token = config['API']['personal_access_token']

print(owner)
print(repo)
print(personal_access_token)

# Github Login Credential
github = login(owner, personal_access_token)

def Log4Shell_read_csv_report(file_name):
    Log4Shell_list_issues = []
    with open(file_name, 'r') as file:
        # read the report
        csv_reader = csv.reader(file)
        # display the contents of the CSV file
        for row in csv_reader:
            Log4Shell_list_issues.append(row)
            # print(row)
    return Log4Shell_list_issues


def Weekly_NAL_read_csv_report(file_name):
    Weekly_NAL_list_issues = []
    with open(file_name, 'r') as file:
        # read the report
        csv_reader = csv.reader(file)
        # display the contents of the CSV file
        for row in csv_reader:
            Weekly_NAL_list_issues.append(row)
    return Weekly_NAL_list_issues


def ARS_BOD_read_csv_report(file_name):
    ARS_BOD_list_issues = []
    with open(file_name, 'r') as file:
        # read the report
        csv_reader = csv.reader(file)
        # display the contents of the CSV file
        for row in csv_reader:
            ARS_BOD_list_issues.append(row)
            print(row)
    return ARS_BOD_list_issues


def verify_duplicates(list):
    # no_dup_unique_ids_list = []
    duplicates_count = 0
    print("\nVerify if duplicates occur in unique identifiers' list")
    for uniq_id in list:
        if list.count(uniq_id) > 1:
            print("Duplicate ids are present in this list")
            duplicates_count += 1
        else:
            print("No duplicates")
    print("Total number of duplicates: ", duplicates_count)


def Log4Shell_create_unique_ids(list):
    print("\nUnique IDs: ")
    print("Length of list: ", len(list))
    Log4Shell_unique_ids_list = []
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

        unique_id = str(list[row][0]) + list[row][1] + str(list[row][3]) + str(list[row][4]) + list[row][12]

        print(unique_id, list[row])
        pair_assigned_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(pair_assigned_unique_id)
    return assigned_unique_ids_list


def Weekly_NAL_create_unique_ids(list):
    print("\nUnique IDs: ")
    print("Length of list: ", len(list))
    Weekly_NAL_unique_ids_list = []
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
        unique_id = str(list[row][0]) + list[row][1] + str(list[row][3]) + str(list[row][4]) + list[row][12]
        Weekly_NAL_unique_ids_list.append(unique_id)

        pair_assigned_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(pair_assigned_unique_id)


    print("list of assigned unique ids:")
    print(assigned_unique_ids_list)

    return assigned_unique_ids_list

def ARS_BOD_create_unique_ids(list):
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
        unique_id = str(list[row][0]) + list[row][1] + str(list[row][3]) + str(list[row][4]) + list[row][19]

        pair_assigned_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(pair_assigned_unique_id)

    return assigned_unique_ids_list


def Log4Shell_create_github_issue(title, labels=None, assignees=None, body=None):
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
    Log4Shell_issue = {
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
    new_repo = session.post(url, json.dumps(Log4Shell_issue))
    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)

def Weekly_NAL_create_github_issue(title, labels=None, assignees=None, body=None):
    # Create an issue on github.com using the given parameters.
    # Our url to create issues via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (owner, repo)
    # Create an authenticated session to create the issue
    session = requests.Session()
    session.auth = (owner, personal_access_token)

    # Create new issues for Weekly NAL Report
    Weekly_NAL_issue = {
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
    new_repo = session.post(url, json.dumps(Weekly_NAL_issue))
    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)

def ARS_BOD_create_github_issue(title, labels=None, assignees=None, body=None):
    # Create an issue on github.com using the given parameters.
    # Our url to create issues via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (owner, repo)
    # Create an authenticated session to create the issue
    session = requests.Session()
    session.auth = (owner, personal_access_token)

    # Create new issues for Weekly NAL Security Report
    ARS_BOD_issue = {
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
    new_repo = session.post(url, json.dumps(ARS_BOD_issue))
    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)

def create_sets(list):
    list.split()
    for i in list.split():
        print(i)

def delay_API_requests():
    delay_in_sec = int(config['API']['delay'])
    time.sleep(delay_in_sec)

# Create hash object from "gitconfig.ini" configuration file
# to read in weekly csv security report related to "Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv"
Log4Shell_report = config['security-csv-reports']['Log4Shell_report']

# Create hash object from "gitconfig.ini" configuration file
# to read in weekly csv security reports related to "Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv"
Weekly_NAL_report = config['security-csv-reports']['Weekly_NAL_report']

# Create hash object from "gitconfig.ini" configuration file
# to read in weekly csv reports related to "ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan Report.csv"
ARS_BOD_report = config['security-csv-reports']['ARS_BOD_report']

try:
    # all_unique_ids_list = []
    print("Log4Shell report:")
    Log4Shell_issues_list = []
    Log4Shell_issues_list = Log4Shell_read_csv_report(Log4Shell_report)

    # Create Log4Shell header to security reports headers
    Log4Shell_header = Log4Shell_issues_list.pop(0)

    # print all issues of Log4Shell security report without header
    print("\n(No header)Length of Log4Shell List of issues:", len(Log4Shell_issues_list))
    for issue in range(len(Log4Shell_issues_list)):
        print(Log4Shell_issues_list[issue])
        # all_unique_ids_list.append(Log4Shell_list_issues[i])


    verify_duplicates(Log4Shell_issues_list)
    Log4Shell_no_dupl_all_issues_list = Log4Shell_create_unique_ids(Log4Shell_issues_list)


    print("Debug Log4Shell_no_dupl_all_issues list")
    print(Log4Shell_no_dupl_all_issues_list[0:5])
    print("Debug Log4Shell_no_dupl_all_issues list")
    print(Log4Shell_no_dupl_all_issues_list[0:5])

    print("Incremental Test: ")
    start = 0
    end = len(Log4Shell_no_dupl_all_issues_list)
    step = 5

    list_increments = []
    for i in range(0, len(Log4Shell_no_dupl_all_issues_list), step):
        x = i
        print("Debugging x")
        print(x)
        list_increments.append(Log4Shell_no_dupl_all_issues_list[x:x + step])
        # Log4Shell_create_github_issue(unique_id, ["Test Label"], ["brian-mustafa"], unique_ids_list)t
        # delay_API_requests()
        print("List of increments: ")
        list_increments[0:5]
        print(Log4Shell_no_dupl_all_issues_list[x:x+step])

        unique_id = Log4Shell_no_dupl_all_issues_list[i][0]
        print(unique_id)
        print("Unique IDs List (Log4Shell): ")
        #unique_ids_list = Log4Shell_no_dupl_all_issues_list[i][1]
        unique_ids_list = Log4Shell_no_dupl_all_issues_list[i][1]
        print("Unique IDs List: ",unique_ids_list)
        #Log4Shell_create_github_issue(unique_id, ["Test Label"], ["brian-mustafa"], unique_ids_list)
        #delay_API_requests()
    
    print("New List of increments")
    print(list_increments)
    print("Log4Shell_no_dupl_all_issues+list[]")
    Log4Shell_no_dupl_all_issues_list[x:x + step]

    # Iterate through unique identifiers (no duplicates) to pass each issue
    # into Log4Shell_create_github_issue() function
    print("\nCreate issues from Log4Shell Report: ")


    for issue in range(len(Log4Shell_no_dupl_all_issues_list)):

        unique_id = Log4Shell_no_dupl_all_issues_list[issue][0]

        unique_ids_list = Log4Shell_no_dupl_all_issues_list[issue][1]

        print("&*Test")
        print(unique_ids_list)
        
        delay_API_requests()
        Log4Shell_create_github_issue(unique_id, ["Test Label"], ['brian-mustafa'], unique_ids_list)



    print("\nWeekly NAL Report:")

    Weekly_NAL_issues_list = []
    Weekly_NAL_issues_list = Weekly_NAL_read_csv_report(Weekly_NAL_report)

    Weekly_NAL_header = Weekly_NAL_issues_list.pop(0)
    print("(No header)Length of Weekly NAL list_issues:", len(Weekly_NAL_issues_list))
    print("(No header) List of Weekly NAL reports' issues:")

    for issue in range(len(Weekly_NAL_issues_list)):
        print(Weekly_NAL_issues_list[issue])
        # all_unique_ids_list.append(Weekly_NAL_issues_list[j])
        # unique_ids_list.append(Log4Shell_list_issues[row])

    # verify duplicates in Weekly NAL reports
    verify_duplicates(Weekly_NAL_issues_list)
    # Weekly_NAL_create_unique_ids(Weekly_NAL_issues_list)
    Weekly_NAL_no_dupl_all_issues_list = Weekly_NAL_create_unique_ids(Weekly_NAL_issues_list)

    # Iterate through unique identifiers (no duplicates) to pass each issue
    # into Weekly_NAL_create_github_issue() function
    print("\n\nCreate issues from Weekly NAL Report: ")

    for issue in range(len(Weekly_NAL_no_dupl_all_issues_list)):

        unique_id = Weekly_NAL_no_dupl_all_issues_list[issue][0]

        unique_ids_list = Weekly_NAL_no_dupl_all_issues_list[issue][1]

        print("Unique IDs List")
        print(unique_ids_list)
        print(Weekly_NAL_no_dupl_all_issues_list[issue][1][0])

        delay_API_requests()

        Log4Shell_create_github_issue(unique_id, ["Test Label"], ['brian-mustafa'], unique_ids_list)

    print("\nARS BOD Report:")

    ARS_BOD_no_dupl_all_issues_list = []
    ARS_BOD_no_dupl_all_issues_list = ARS_BOD_read_csv_report(ARS_BOD_report)

    # Verify that each unique identifier for ARS BOD Report is returned
    for issue in range(len(ARS_BOD_no_dupl_all_issues_list)):
        print(ARS_BOD_no_dupl_all_issues_list[issue])

    # Remove header of ARS BOD Report
    ARS_BOD_header = ARS_BOD_no_dupl_all_issues_list.pop(0)
    print("(No header)Length of ARS BOD reports' list of issues:", len(ARS_BOD_no_dupl_all_issues_list))
    print("(No header) list of issues (ARS_BOD):")

    verify_duplicates(ARS_BOD_no_dupl_all_issues_list)
    ARS_BOD_no_dupl_all_issues_list = ARS_BOD_create_unique_ids(ARS_BOD_no_dupl_all_issues_list)

    # Iterate through unique identifiers (no duplicates) to pass each issue
    # into ARS_BOD_create_github_issue() function
    print("\nCreate issues from ARS BOD Report: ")

    for issue in range(len(ARS_BOD_no_dupl_all_issues_list)):
        print("ARS_BOD_no_dupl_all_issues_list[i][0]")
        print(ARS_BOD_no_dupl_all_issues_list[issue][0])
        unique_id = ARS_BOD_no_dupl_all_issues_list[issue][0]
        unique_ids_list = ARS_BOD_no_dupl_all_issues_list[issue][1]

        delay_API_requests()
        ARS_BOD_create_github_issue(unique_id, ["Test Label"], ['brian-mustafa'], unique_ids_list)

except AttributeError:
    print("Attribute Error.")
except EOFError:
    print("EOF Error is raised when the input() function hits the end-of-file condition")
except Exception:
    print("An unknown error occurred.")
except FileNotFoundError:
    print("No such file or directory solution.")
except ImportError:
    print("Import Error. Import module is not found.")
except IndentationError:
    print("IndentationError is raised when there is an incorrect indentation.")
except IndexError:
    print("Index Error. Index of a sequences(s) is out of range.")
except IOError:
    print("IOError.")
except KeyboardInterrupt:
    print("Keyboard Interrupt is raised when the user hits the interrupt key")
except MemoryError:
    print("Memory Error.")
except NameError:
    print("Name Error is raised when a variable is not found in the local or global scope.")
except NotImplementedError:
    print("NotImplementedError is raised by abstract methods.")
except OSError:
    print("OS Error. If system operation causes system related error.")
except ReferenceError:
    print("Reference Error is raised when a weak reference proxy is used to access a garbage collected referent.")
except RuntimeError:
    print("RunTime Error. Error does not fall in any pre-existing category.")
except StopIteration:
    print(
        "StopIteration is raised by the next() function to indicate that there is no further item to be returned by the iterator.")
except SyntaxError:
    print("Syntax Error.")
except SystemError:
    print("System Error. If interpreter detects internal error.")
except TabError:
    print("Tab Error is raised when the indentation consists of inconsistent tabs and spaces")
except UnboundLocalError:
    print(
        "Unbound Local Error is raised when a reference is made to a local variable in a function or method but no value has been bound to that variable.")
except UnicodeError:
    print("Unicode Error. Unicode-related encoding or decoding error occured")
except UnicodeEncodeError:
    print("UnicodeEncode Error is raised when a Unicode-related error occurs during encoding.")
except UnicodeDecodeError:
    print("UnicodeDecodeError is raised when a Unicode-related error occurs during decoding.")
except UnicodeTranslateError:
    print("UnicodeTranslateError is raised when a Unicode-related error occurs during translation.")
except ValueError:
    print("Value Error occurs if a function receives a value of correct type but an improper value.")
except ZeroDivisionError:
    print("ZeroDivisionError is raised when the second operand of a division or module operation is zero.")