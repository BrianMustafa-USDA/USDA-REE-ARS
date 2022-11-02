import csv
import configparser
import json
import requests
import os
import time
from github3 import login
from pathlib import Path
# from threading import Event
# from threading import Thread

# ConfigParser Object
config = configparser.ConfigParser()

# Read "gitconfig.ini"
config.read("gitconfig.ini")

# Read config.sections()
config.sections()

'''
for key, value in config:
    print(key, value)
'''
print("Print github-api-test-user")
for key in config['user']:
    print(key)

print(config['API']['personal_access_token'])
print(type(config['API']['personal_access_token']))

owner = config['user']['owner']
repo = config['user']['repo']
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
        print("row")
        print(row)
        print("list[row]")
        print(list[row])
        print("list of unique id, list[row]")
        print(unique_id, list[row])
        pair_assigned_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(pair_assigned_unique_id)

    '''
    print("\nAll assigned_unique_ids_list: ")
    print("Length of unique ids list: ", len(assigned_unique_ids_list))
    print("assigned_unique_ids_list[0]")
    print(assigned_unique_ids_list[0])
    print("assigned_unique_ids_list[0][1])")
    print(assigned_unique_ids_list[0][1])
    print("assigned_unique_ids_list[0][1])[0]")
    print(assigned_unique_ids_list[0][1][0])
    print("assigned_unique_ids_list[0][1][3]")
    print(assigned_unique_ids_list[0][1][3])

    print("This is the list of assigned unique ids:")
    print(assigned_unique_ids_list)
    '''
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
        print(type(unique_id))
        print(unique_id)

        print("row")
        print(row)
        print("list[row]")
        print(list[row])
        print("list of unique id, list[row]")
        print(unique_id, list[row])
        pair_assigned_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(pair_assigned_unique_id)

    '''
    print("\nAll assigned_unique_ids_list: ")
    print("Length of unique ids list: ", len(assigned_unique_ids_list))
    print("assigned_unique_ids_list[0]")
    print(assigned_unique_ids_list[0])
    print("assigned_unique_ids_list[0][1])")
    print(assigned_unique_ids_list[0][1])
    print("assigned_unique_ids_list[0][1])[0]")
    print(assigned_unique_ids_list[0][1][0])
    print("assigned_unique_ids_list[0][1][3]")
    print(assigned_unique_ids_list[0][1][3])

    print("list of assigned unique ids:")
    print(assigned_unique_ids_list)
    '''
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

        '''
        print("row")
        print(row)
        print("list[row]")
        print(list[row])
        print("list of unique id, list[row]")
        print(unique_id, list[row])
        pair_assigned_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(pair_assigned_unique_id)
        '''

    '''
    print("list of assigned unique ids:")
    print(assigned_unique_ids_list)
    '''
    return assigned_unique_ids_list


def Log4Shell_create_github_issue(title, labels=None, assignees=None):
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
### Plugin: {each_unique_id_list[0]}
### Plugin Name: {each_unique_id_list[1]}
### Severity: {each_unique_id_list[2]}
### IP Address: {each_unique_id_list[3]}
### Port: {each_unique_id_list[4]}
### DNS Name: {each_unique_id_list[5]}
### NetBios Name: {each_unique_id_list[6]}
### Plugin Output: {each_unique_id_list[7]}
### Solution: {each_unique_id_list[8]}
### CVSS V3 Base Score: {each_unique_id_list[9]}
### CVE: {each_unique_id_list[10]}
### First Discovered: {each_unique_id_list[11]}
### Last Observed: {each_unique_id_list[12]}
'''
    }

    # Add the issue to our repository
    new_repo = session.post(url, json.dumps(Log4Shell_issue))
    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)
    '''
    delay_in_sec = int(config['API']['delay'])
    time.sleep(delay_in_sec)

    res = requests.request("GET", url, headers=headers)
    res = res.headers["Retry-After"]
    print("Retry-After: ")
    print(int(res))
    '''

    '''
    r = requests.get("https://github.com/isdapps/IT-Security-Test/issues")
    print("r.text")
    r.text
    print(r.json())
    '''


def Weekly_NAL_create_github_issue(title, labels=None, assignees=None):
    # Create an issue on github.com using the given parameters.
    # Our url to create issues via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (owner, repo)
    # Create an authenticated session to create the issue
    session = requests.Session()
    session.auth = (owner, personal_access_token)
    '''
    Pseudocode:
    Iterate through each issue to assign unique identifier to "title"
    '''
    # Create new issues for Weekly NAL & ARS BOD Report
    Weekly_NAL_issue = {
        'title': title,  # assign each new issue to title
        'labels': labels,
        'assignees': assignees,
        'body':
            f'''             
### Plugin: {each_unique_id_list[0]}
### Plugin Name: {each_unique_id_list[1]}
### Severity: {each_unique_id_list[2]}
### IP Address: {each_unique_id_list[3]}
### Port: {each_unique_id_list[4]}
### DNS Name: {each_unique_id_list[5]}
### NetBios Name: {each_unique_id_list[6]}
### Plugin Output: {each_unique_id_list[7]}
### Solution: {each_unique_id_list[8]}
### CVSS V3 Base Score: {each_unique_id_list[9]}
### CVE: {each_unique_id_list[10]}
### First Discovered: {each_unique_id_list[11]}
### Last Observed: {each_unique_id_list[12]}
'''
    }
    # Add the issue to our repository
    new_repo = session.post(url, json.dumps(Weekly_NAL_issue))
    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)
    '''
    delay_in_sec = int(config['API']['delay'])
    time.sleep(delay_in_sec)
    '''


def ARS_BOD_create_github_issue(title, labels=None, assignees=None):
    # Create an issue on github.com using the given parameters.
    # Our url to create issues via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (owner, repo)
    # Create an authenticated session to create the issue
    session = requests.Session()
    session.auth = (owner, personal_access_token)
    '''
    Pseudocode:
    Iterate through each issue to assign unique identifier to "title"
    '''
    # Create new issues for Weekly NAL Security Report
    ARS_BOD_issue = {
        'title': title,  # assign each new issue to title
        'labels': labels,
        'assignees': assignees,
        'body':
            f'''             
### Plugin: {each_unique_id_list[0]}
### Plugin Name: {each_unique_id_list[1]}
### Family: {each_unique_id_list[2]}
### Severity: {each_unique_id_list[3]}
### IP Address: {each_unique_id_list[4]}
### Port: {each_unique_id_list[5]}
### MAC Address: {each_unique_id_list[6]}
### DNS Name: {each_unique_id_list[7]}
### NetBios Name: {each_unique_id_list[8]}
### Plugin Output: {each_unique_id_list[9]}
### Synopsis: {each_unique_id_list[10]}
### Description: {each_unique_id_list[11]}
### Solution: {each_unique_id_list[12]}
### Vulnerability Priority Rating: {each_unique_id_list[13]}
### CVSS V2 Base Score: {each_unique_id_list[14]}
### CVSS V3 Base Score: {each_unique_id_list[15]}
### CPE: {each_unique_id_list[16]}
### CVE: {each_unique_id_list[17]}
### First Discovered: {each_unique_id_list[18]}
### Last Observed: {each_unique_id_list[19]}
### Cross References: {each_unique_id_list[20]}
'''
    }
    # Add the issue to our repository
    new_repo = session.post(url, json.dumps(ARS_BOD_issue))
    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)

    '''    
    delay_in_sec = int(config['API']['delay'])
    time.sleep(delay_in_sec)
    '''


Log4Shell_report = config['security-csv-reports']['Log4Shell_report']
Weekly_NAL_report = config['security-csv-reports']['Weekly_NAL_report']
ARS_BOD_report = config['security-csv-reports']['ARS_BOD_report']

try:
    '''
    with os.scandir("my directory") as entries:
        print("entries")


    #Display all of csv files in server directory 
    entries = Path("directory/")
    for entry in entries.iterdir():
        print(entry.name)
    '''

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

    # Iterate through unique identifiers (no duplicates) to pass each issue
    # into Log4Shell_create_github_issue() function
    print("\nCreate issues from Log4Shell Report: ")
    print("Log4Shell_no_dupl_all_issues_left")
    print("Length of Log4Shell:", )
    for issue in range(len(Log4Shell_no_dupl_all_issues_list)):
        '''
        print("for i in range(len(Log4Shell_no_dupl_all_issues_list))")
        print(issue)
        print("(10-04)Log4Shell_no_dupl_all_issues_list[i][0]:")
        print(Log4Shell_no_dupl_all_issues_list[issue][0])
        '''
        each_unique_id = Log4Shell_no_dupl_all_issues_list[issue][0]
        '''
        print("(10-04)Log4Shell_no_dupl_all_issues_list[i][1]:")
        print(Log4Shell_no_dupl_all_issues_list[issue][1])
        '''
        each_unique_id_list = Log4Shell_no_dupl_all_issues_list[issue][1]
        '''
        print("Plugin - (10-04)Log4Shell_no_dupl_all_issues_list[i][1][0]:")
        print(Log4Shell_no_dupl_all_issues_list[issue][1][0])
        '''

        delay_in_sec = int(config['API']['delay'])
        time.sleep(delay_in_sec)
        Log4Shell_create_github_issue(each_unique_id, ["Test Label"], ['brian-mustafa'], each_unique_id_list)

    '''
    # Remove previous file
    if os.path.exists(Log4Shell_report):
        print("Remove previous_Log4Shell_report")
        os.remove(Log4Shell_report)
    else:
        print("Log4Shell file does not exist")
    '''

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

    # verify duplciates in Weekly NAL reports
    verify_duplicates(Weekly_NAL_issues_list)
    # Weekly_NAL_create_unique_ids(Weekly_NAL_issues_list)
    Weekly_NAL_no_dupl_all_issues_list = Weekly_NAL_create_unique_ids(Weekly_NAL_issues_list)

    # Iterate through unique identifiers (no duplicates) to pass each issue
    # into Weekly_NAL_create_github_issue() function
    print("\n\nCreate issues from Weekly NAL Report: ")

    for issue in range(len(Weekly_NAL_no_dupl_all_issues_list)):
        print("for i in range(len(Weekly_NAL_no_dupl_all_issues_list))")
        print(issue)
        print("(10-04)Weekly_NAL_no_dupl_all_issues_list[i][0]:")
        print(Weekly_NAL_no_dupl_all_issues_list[issue][0])
        each_unique_id = Weekly_NAL_no_dupl_all_issues_list[issue][0]
        print("(10-04)Log4Shell_no_dupl_all_issues_list[i][1]:")
        print(Weekly_NAL_no_dupl_all_issues_list[issue][1])
        each_unique_id_list = Weekly_NAL_no_dupl_all_issues_list[issue][1]
        print("Plugin - Weekly_NAL_no_dupl_all_issues_list[i][1][0]:")
        print(Weekly_NAL_no_dupl_all_issues_list[issue][1][0])

        delay_in_sec = int(config['API']['delay'])
        time.sleep(delay_in_sec)
        Log4Shell_create_github_issue(each_unique_id, ["Test Label"], ['brian-mustafa'], each_unique_id_list)

    '''
    # Remove previous file
    if os.path.exists(Weekly_NAL_report):
        print("Remove previous Weekly NAL Report")
        os.remove(Weekly_NAL_report)
    else:
        print("Weekly NAL Report does not exit")
    '''

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
        each_unique_id = ARS_BOD_no_dupl_all_issues_list[issue][0]
        print("ARS_BOD_no_dupl_all_issues_list[i][1]")
        each_unique_id_list = ARS_BOD_no_dupl_all_issues_list[issue][1]

        delay_in_sec = int(config['API']['delay'])
        time.sleep(delay_in_sec)
        ARS_BOD_create_github_issue(each_unique_id, ["Test Label"], ['brian-mustafa'], each_unique_id_list)
    '''
    # Remove previous file
    if os.path.exists(ARS_BOD_report):
        print("Remove previous ARS BOD Report")
        os.remove(ARS_BOD_report)
    else:
        print("ARS BOD Report does not exist")
    '''
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
