# Standard Python libraries
import configparser
import csv
import json
import logging
import requests
import subprocess
import time
# Custom Library:
# Source URL: https://github3.readthedocs.io/en/latest/
from github3 import login

# Initializing Basic Configuration File entitled "security_reports_issues_scraper_202303"
logging.basicConfig(filename="security_reports_issues_scraper_202307_test_case_1.log",
                    encoding="utf-8",
                    level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%m/%d/%Y %H:%M:%S")

logging.info("Start Logging")
"""
Read csv file 
entitled "Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv"
"""

def log4shell_read_csv_report(file_name):
    # Create new list entitled "log4shell_issues_list"
    log4shell_issues_list = []
    with open(file_name, "r") as file:
        # read the report into csv_reader object
        csv_reader = csv.reader(file)
        # append each row of csv report to new list entitled "log4shell_issues_list"
        for row in csv_reader:
            log4shell_issues_list.append(row)
    # Return new list entitled "log4shell_issues_list" consisting of each row of issues
    return log4shell_issues_list

"""
Read csv file
entitled "Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv"
"""

def weekly_nal_read_csv_report(file_name):
    # Create new list entitled "weekly_nal_issues_list"
    weekly_nal_issues_list = []
    with open(file_name, "r") as file:
        # read the report
        csv_reader = csv.reader(file)
        # append each row of csv report to new list entitled "weekly_nal_list"
        for row in csv_reader:
            weekly_nal_issues_list.append(row)
    # Return new list entitled "weekly_nal_issues_list" consisting of each row of issues
    return weekly_nal_issues_list

"""
Read csv file
entitled "ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan Report.csv"
"""

def ars_bod_read_csv_report(file_name):
    # Create new list "ars_bod_issues_list"
    ars_bod_issues_list = []
    with open(file_name, "r") as file:
        # read the report
        csv_reader = csv.reader(file)
        # append each row of csv report to new list entitled "weekly_nal_issues_list"
        for row in csv_reader:
            ars_bod_issues_list.append(row)
    # Return new list entitled "ars_bod_issues_list" consisting of each row of issues
    return ars_bod_issues_list

# Verify if more than one copy of the same issue appears in security report.csv files
def verify_duplicates(list):
    # Create counter entitled "duplicates_count" to keep count of all # of duplicates
    duplicates_count = 0
    print("\nVerify if duplicates occur in unique identifiers' list")
    print("Type of list: ", type(list))
    for uniq_id in list:
        if list.count(uniq_id) > 1:
            print("Duplicate ids are present in this list")
            print("uniq_id: ", uniq_id)
            duplicates_count += 1
            list.pop(uniq_id)
        else:
            print("No duplicates")
    print("Total number of duplicates: ", duplicates_count)
    return list

"""
# Verify if more than one of the same issue appears in each of the security report.csv files
def verify_duplicates(list):
    # Create counter entitled "duplicates_count" to keep track of the number of duplicates
    dupl_counter = 0
    dupl_list = []
    print("\nVerify if duplicates occur in unique identifiers' list")
    for uniq_id in list:
        if list.count(uniq_id) > 1:
            print("Duplicate ids are present in this list")
            dupl_counter += 1
            #dupl_list.append()
            list.pop(uniq_id)
            # Add a new comment to most recent duplicate issue using "Last Observed" field in body field
            #if uniq_id == uniq_id:
        else:
            print("No duplicates")
    print("Total number of duplicates: ", dupl_counter)
    return no_dupl_list
"""

"""
Create log4shell_create_unique_ids() function to 
pass list object "list" of unique identifier fields
in order to parse and create unique identifiers from "Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv"
"""

def verify_duplicates_of_unique_ids(list):
    uniq_list = []
    dupl_list = []
    dupl_count = 0
    for each_issue in list:
        if each_issue not in uniq_list:
            uniq_list.append(each_issue)  # Append each new non-duplicate unique issue to uniq_list
        else:
            dupl_list.append(each_issue)  # Capture each duplicate unique id in dupl_list
            dupl_count += 1  # Incremental count by 1
    """
    print("(log4shell) dupl_list: ", dupl_list)
    print("(log4shell) uniq_list: ", uniq_list)
    print("Total # of duplicates: ", dupl_count)
    """
    return dupl_list

def log4shell_create_unique_ids_list(list):
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

        print("Unique ID of log4shell_issues: ", unique_id)
        log4shell_unique_ids_list.append(unique_id)
        #dupl_uniq_ids_list = verify_duplicates_of_unique_ids(log4shell_unique_ids_list)

        print("unique_id, list[row]: ", unique_id, list[row])
        assigned_pair_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ", assigned_pair_unique_id)
        assigned_unique_ids_list.append(assigned_pair_unique_id)

    return assigned_unique_ids_list

def send_last_observed_timestamp(list):
    for row in range(len(list)):
        # Last Observed Timestamp
        # list[row][12] -> Column: Last Observed
        last_observed_timestamp = list[row][12]
    return last_observed_timestamp

"""
Create weekly_nal_create_unique_ids() function to 
pass list object  to create unique identifiers from "Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv"
"""

def weekly_nal_create_unique_id(list):
    print("\nUnique ID: ")
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

        assigned_pair_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(assigned_pair_unique_id)
    print("list of assigned unique ids:")
    print(assigned_unique_ids_list)
    return assigned_unique_ids_list

"""
Create ars_bod_create_unique_ids() function to 
pass list object "list" to create unique identifiers from "ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan Report.csv"
"""

def ars_bod_create_unique_id(list):
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

def all_unique_ids(list):
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

def log4shell_create_github_issue(
        title, labels=None,
        assignees=None, body=None):
    # Display message to log file to indicate program is connecting into https://api.github.com
    logging.info("""Connecting into https://api.github.com in order to create issue on 
    <Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv>""")

    # Create an issue on https://api.github.com using the given parameters.
    # Our url to create issues via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (owner, repo)

    # Display message in log file of logging into repo
    logging.info("Logging into repo <%s>" % repo)
    # Create an authenticated session to create the issue in security report
    with requests.Session() as session:
        session = requests.Session()
        session.auth = (owner, personal_access_token)
    try:
        session.post(url)
        logging.info("Successfully created session")
    except ConnectionError as ce:
        print(ce)
        logging.error("Connection Error")

    # for unique_id in Security_Report:
    # create dict of each issue entitled "log4shell_issue"
    log4shell_issue = {
        'title': title,  # assign each new issue to title
        'labels': labels,
        'assignees': assignees,
        'body':
f'### Plugin: {unique_ids_list[0]}'
f'### Plugin Name: {unique_ids_list[1]}'
f'### Severity: {unique_ids_list[2]}'
f'### IP Address: {unique_ids_list[3]}'
f'### Port: {unique_ids_list[4]}'
f'### DNS Name: {unique_ids_list[5]}'
f'### NetBios Name: {unique_ids_list[6]}'
f'### Plugin Output: {unique_ids_list[7]}'
f'### Solution: {unique_ids_list[8]}'
f'### CVSS V3 Base Score: {unique_ids_list[9]}'
f'### CVE: {unique_ids_list[10]}'
f'### First Discovered: {unique_ids_list[11]}'
f'### Last Observed: {unique_ids_list[12]}'
    }
    # Serialize session object and convert data type of log4shell_issue from dict to json string to be processed via POST
    new_repo = session.post(url, json.dumps(log4shell_issue))

    # HTTP response status code 201 indicates that the issue was successfully created
    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
        logging.info('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)
        logging.error('Could not create Issue {0:s}'.format(title))
        logging.error('Response: ', new_repo.content)
    return log4shell_issue

"""
def add_updated_timestamp_comment_of_most_recent_issue(owner, repo):
    # Display message to log file to indicate program is connecting into https://api.github.com
    logging.info("Add new comment with most recent updated timestamp")

    #Create a response object called r

    #Send request

    r = requests.patch('https://api.github.com/repos/%s/%s/issues/%s / patch' % (owner, repo, comment_id), data={'key':'value'} )
    print('r object: ', r)
    #await session.request('PATCH /repos/{owner}/{repo}/issues/comments/{comment_id}', )
    return r
"""

def weekly_nal_create_github_issue(
        title, labels=None,
        assignees=None, body=None):
    # Display message to log file to indicate program is connecting into https://api.github.com
    logging.info("""Connecting into https://api.github.com in order to create issue on 
        <Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv>""")
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
f'### Plugin: {unique_ids_list[0]}'
f'### Plugin Name: {unique_ids_list[1]}'
f'### Severity: {unique_ids_list[2]}'
f'### IP Address: {unique_ids_list[3]}'
f'### Port: {unique_ids_list[4]}'
f'### DNS Name: {unique_ids_list[5]}'
f'### NetBios Name: {unique_ids_list[6]}'
f'### Plugin Output: {unique_ids_list[7]}'
f'### Solution: {unique_ids_list[8]}'
f'### CVSS V3 Base Score: {unique_ids_list[9]}'
f'### CVE: {unique_ids_list[10]}'
f'### First Discovered: {unique_ids_list[11]}'
f'### Last Observed: {unique_ids_list[12]}'
    }
    # Add the issue to our repository
    new_repo = session.post(url, json.dumps(weekly_nal_issue))

    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
        logging.info('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)
        logging.error('Could not create Issue {0:s}'.format(title))
        logging.error('Response: ', new_repo.content)

def ars_bod_create_github_issue(
        title, labels=None,
        assignees=None, body=None):
    # Display message to log file to indicate program is connecting into https://api.github.com
    logging.info("""Connecting into https://api.github.com in order to create issue on 
            <ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan Report.csv>""")
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
f'### Plugin: {unique_ids_list[0]}'
f'### Plugin Name: {unique_ids_list[1]}'
f'### Family: {unique_ids_list[2]}'
f'### Severity: {unique_ids_list[3]}'
f'### IP Address: {unique_ids_list[4]}'
f'### Port: {unique_ids_list[5]}'
f'### MAC Address: {unique_ids_list[6]}'
f'### DNS Name: {unique_ids_list[7]}'
f'### NetBios Name: {unique_ids_list[8]}'
f'### Plugin Output: {unique_ids_list[9]}'
f'### Synopsis: {unique_ids_list[10]}'
f'### Description: {unique_ids_list[11]}'
f'### Solution: {unique_ids_list[12]}'
f'### Vulnerability Priority Rating: {unique_ids_list[13]}'
f'### CVSS V2 Base Score: {unique_ids_list[14]}'
f'### CVSS V3 Base Score: {unique_ids_list[15]}'
f'### CPE: {unique_ids_list[16]}'
f'### CVE: {unique_ids_list[17]}'
f'### First Discovered: {unique_ids_list[18]}'
f'### Last Observed: {unique_ids_list[19]}'
f'### Cross References: {unique_ids_list[20]}'
    }
    # Add the issue to our repository
    new_repo = session.post(url, json.dumps(ars_bod_issue))

    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
        logging.info('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)
        logging.error('Could not create Issue {0:s}'.format(title))
        logging.error('Response: ', new_repo.content)

def create_most_recent_timestamp_comment_of_duplicate_issue(title, labels=None, assignees=None, body=None):
    # Create an issue comment for each existing duplicate issue in repo
    try:
        subprocess.run(["/home/brian.mustafa/", "c.sh", "5"], timeout=10, check=True)
    except FileNotFoundError as exc:
        print(f"Process failed because the executable could not be found.\n{exc}")
    except subprocess.CalledProcessError as exc:
        print(
            f"Process failed because did not return a successful return code. "
            f"Returned {exc.returncode}\n{exc}"
        )
    except subprocess.TimeoutExpired as exc:
        print(f"Process timed out.\n{exc}")

    # Pass variable assigned to issue_number into url
    # issue_number

    # Our url to create issue comments via POST
    url = "https://api.github.com/repos/%s/%s/issues/%s/comments" % (owner, repo, issue_number)

    # Display message in log file of logging into repo
    logging.info("Logging into repo %s" % repo)
    # Create an authenticated session to create the issue in security report
    with requests.Session() as session:
        session = requests.Session()
        session.auth = (owner, personal_access_token)
    try:
        session.post(url)
        logging.info("Successfully created session")
    except ConnectionError as ce:
        print(ce)
        logging.error("Connection Error")

    # create issue comment of duplicate
    duplicate_issue_comment = {
f'### body': 'Last Created: {}'
    }
    # Add issue comment of most recent duplicate issues to previously created issue in our repository
    new_repo = session.post(url, json.dumps(duplicate_issue_comment))

"""
create a function to add a new comment "last observed" field of new duplicate issue
"""

# Remove header (1st row) of each .csv report
def remove_header(list):
    list.pop(0)
    return list

def delay_api_requests():
    delay_in_sec = int(config['API']['delay'])
    time.sleep(delay_in_sec)

# Create and assign ConfigParser Object to retrieve configuration data from config.ini
config = configparser.ConfigParser()

# Read "config file."
config.read("security_reports_issues_scraper.conf")

# Assign owner of [user] from config.ini
owner = config["user"]["owner"]

# Assign repo of [user] from config.ini
repo = config["user"]["repo"]

# Assign personal_access_token within [API] in config file.
personal_access_token = config["API"]["personal_access_token"]

# Assign delimiter within [unique-id-title] in config.ini
unique_id_title_delimiter = config["unique-id-title"]["delimiter"]

"""
Create hash object from "config file." configuration file
to read in weekly security report related to "Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report
- CHML Vulns  7 Days.csv"
"""
log4shell_report = config['security-csv-reports']['Log4Shell_report']
"""
logging.info("Checking if security report <%s> exists." %log4shell_report)
if log4shell_report:
    logging.info("Security Report <%s> exists." % log4shell_report)
else:
    logging.error("Security Report <%s> does not exist." % log4shell_report)
"""

"""
Create hash object from "config file." configuration file
to read in weekly csv security reports related to "Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML
Vulns  7 Days.csv"
"""
weekly_nal_report = config['security-csv-reports']['Weekly_NAL_report']
"""
Create hash object from "config file." configuration file
to read in weekly csv reports related to "ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan
Report.csv"
"""
ars_bod_report = config['security-csv-reports']['ARS_BOD_report']
'''
Personal Access Token:
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
'''
# Enter Github Login Credential
"""
github = login(owner, personal_access_token)
print("Login information from Github")
#logging.info("")
"""
"""
FileNotFoundError: [Errno 2] No such file or directory: 'Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv'
"""

"""
logging.info("Checking if security report <%s> exists." % log4shell_report)
    if log4shell_report:
        logging.info("Security Report <%s> exists." % log4shell_report)
    else:
        logging.error("FileNotFoundError. Security Report <%s> does not exist." % log4shell_report)
"""

# Starting security_reports_issues_scraper.py
logging.info("Successfully started execution of <security_reports_issues_scraper.py>")

# Enter Github Login Credential
github = login(owner, personal_access_token)

"""
if github == login(owner, personal_access_token):
    logging.info("Successfully logged into repo <isdapps/IT-Security-Test>.")
else:
    logging.error("Unable to log into repo <isdapps/IT-Security-Test> using current login credentials.")
"""

print("Log4Shell report:")

"""
logging.info("Checking if security report <%s> exists." % log4shell_report)
if log4shell_report:
    logging.info("Security Report <%s> exists." % log4shell_report)
else:
    logging.error("Security Report <%s> does not exist." % log4shell_report)
"""

"""
logging.info(
    "Processing Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> to create issues.")
"""

log4shell_issues_list = []
log4shell_issues_list = log4shell_read_csv_report(log4shell_report)
'''
# Create Log4Shell header to security reports headers
'''
log4shell_no_header_issues_list = remove_header(log4shell_issues_list)
print("No header list: ", log4shell_no_header_issues_list)
# print length of all issues of Log4Shell security report without header
print("\n(No header)Total Number of issues: ", len(log4shell_no_header_issues_list))
print("Type of log4shell_no_header_issues_list: ", type(log4shell_no_header_issues_list))
"""
for issue in range(len(log4shell_no_header_issues_list)):
    print(log4shell_no_header_issues_list[issue])
"""

# 2nd method to verify duplicates in Log4Shell report

"""
dup = {x for x in log4shell_no_header_issues_list if log4shell_no_header_issues_list.count(x) > 1}
print("dup: ", dup)
print("len of duplicate issues in header: ", len(dup))
"""
log4shell_no_dupl_all_issues_list = verify_duplicates(log4shell_no_header_issues_list)
print("verified log4shell_issues")

# create unique ids for each issue in security report
log4shell_unique_ids_list = log4shell_create_unique_ids_list(log4shell_no_dupl_all_issues_list)

#print("log4shell_no_dupl_all_unique_ids_list", log4shell_no_dupl_all_unique_ids_list)

# Iterate through unique identifiers (no duplicates) to pass each issue
# into Log4Shell_create_github_issue() function
print("\nCreate issues from Log4Shell Report: ")

"""
# Iterate and create each issue in "Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> exists."
# onto the repo
"""
# return issue number of most recently created issue on Github
#s = requests.Session()

"""
comment_id = 44242
r = requests.get("https://api.github.com/repos/%s/%s/issues/comments/%s" % (owner, repo, comment_id))
#print("Issue number of r.json: ", r.json())
print("r.headers: ", r.headers)
print("r.status_code:", r.status_code)
print("r.json() to terminal:")
print(r.json())
"""
#s = requests.Session()

#url = 'https://api.github.com/repos/%s/%s/issues/comments' % (owner, repo)
url = 'https://api.github.com/' + '/repos/' + '/' + owner + '/' + repo + '/' + '/issues/comments'
#url = 'https://api.github/com/get/repos//issues/comments'
headers = {'X-GitHub-Api-Version': '2022-11-28'}
r = requests.get(url, auth = (owner, personal_access_token), headers=headers)
print(r.url)
print(r.status_code)
print("r.text ")


"""
with requests.Session() as session:
    session = requests.Session()
    session.auth = (owner, personal_access_token)
try:
    session.post(url)
    logging.info("Successfully created session")
except ConnectionError as ce:
    print(ce)
    logging.error("Connection Error")
"""

# print("session.json(): ", r.json())

for issue in range(len(log4shell_unique_ids_list)):
    print("(1)Issue in log4shell_no_dupl_all_issues_list")
    #print(issue)
    unique_id = log4shell_unique_ids_list[issue][0]
    #dupl_list = verify_duplicates(unique_id)
    print("Log4Shell Unique_id: ")
    #print(unique_id)
    print("New Unique_ids_list")
    unique_id_list = log4shell_unique_ids_list[issue][1]
    #print("Unique_ids_list compilation: ", unique_id_list)

    # Compare most recently created issue with previously created issue to detect duplicate issues w/ same unique id
    dupl_unique_ids_list = verify_duplicates_of_unique_ids(log4shell_unique_ids_list)
    print("Duplicate issue with same unique_id in repository")

    if unique_id in dupl_unique_ids_list:
        print("Duplicate issue with same unique_id in repository")
        # return issue number of most recently created issue on Github
        #s = requests.Session()
        #r = s.post("https://api.github.com/%s/%s/issues" % (owner, repo))
        #print("Issue number of r.content: ", r.content)
        #create_new_github_issue[log4shell_create_github_issue]
        last_observed_timestamp = send_last_observed_timestamp(dupl_unique_ids_list)
        create_most_recent_timestamp_comment_of_duplicate_issue()

    # Call "delay_api_requests()" function to execute delay_in_sec initialized in config file.
    delay_api_requests()

    # Create each issue on github from Log4Shell Report
    # new_issue = log4shell_create_github_issue(unique_id, ["Test Label"], ["brian-mustafa"], unique_id_list)

    #verify_duplicates_of_unique_ids(unique_id)
    """
    if new_issue[unique_id] == issue[unique_id]:
        print("Most recent unique id is same as previous unique id")
        # create function to add new comment with most recent timestamp
        # add_new_comment_with_most_recent_timestamp
        # log4shell_create_github_issue()
    else:
        print("Error. Unable to compare unique identifiers.")
    # add_updated_timestamp_comment_of_most_recent_issue()
    """

print("\nWeekly NAL Report:")
weekly_nal_issues_list = []
weekly_nal_issues_list = weekly_nal_read_csv_report(weekly_nal_report)
logging.info(
    "Checking if <Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> report exists.")
logging.error(
    "<Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> does not exist.")

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
# weekly_nal_no_dupl_all_issues_list = weekly_nal_create_unique_id(weekly_nal_no_dupl_all_issues_list)

'''
Iterate through unique identifiers (no duplicates) to pass each issue
into Weekly_NAL_create_github_issue() function
'''
print("\n\nCreate issues from Weekly NAL Report: ")

for issue in range(len(weekly_nal_no_dupl_all_issues_list)):
    unique_id = weekly_nal_no_dupl_all_issues_list[issue][0]
    unique_ids_list = weekly_nal_no_dupl_all_issues_list[issue][1]
    print("(Weekly NAL Report) Unique IDs List")
    print(unique_ids_list)
    print(weekly_nal_no_dupl_all_issues_list[issue][1][0])

    delay_api_requests()

    #weekly_nal_create_github_issue(unique_id, ["Test Label"], ["brian-mustafa"], unique_ids_list)

print("\nARS BOD Report:")
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

# verify duplicates in ARS BOD Report
ars_bod_no_dupl_all_issues_list = verify_duplicates(ars_bod_no_header_issues_list)
print("ars_bod_no_dupl_all_issues_list")
print(ars_bod_no_dupl_all_issues_list)
# ars_bod_create_unique_ids
ars_bod_no_dupl_all_issues_list = ars_bod_create_unique_id(ars_bod_no_dupl_all_issues_list)

# Iterate through unique identifiers (no duplicates) to pass each issue
# into ARS_BOD_create_github_issue() function
print("\nCreate issues from ARS BOD Report: ")

for issue in range(len(ars_bod_no_dupl_all_issues_list)):
    print("ARS_BOD_no_dupl_all_issues_list[i][0]")
    print(ars_bod_no_dupl_all_issues_list[issue][0])
    unique_id = ars_bod_no_dupl_all_issues_list[issue][0]
    unique_ids_list = ars_bod_no_dupl_all_issues_list[issue][1]

    delay_api_requests()
    #ars_bod_create_github_issue(unique_id, ["Test Label"], ["brian-mustafa"], unique_ids_list)

logging.info('Complete Logging')

"""\
except AttributeError:
    print("Attribute Error.")
except EOFError:
    print("EOF Error is raised when the input() function hits the end-of-file condition.")
except FileNotFoundError:
    print("No such file or directory solution.")
    #logging.error("<%s> does not exist" % s)
except IndentationError:
    print("Indentation Error is raised when there is an incorrect indentation.")
except IndexError:
    print("Index Error. Index of a sequences(s) is out of range.")
except KeyboardInterrupt:
    print("Keyboard Interrupt is raised when the user hits the interrupt key")
except NameError:
    print("name {} is no defined.")
    #logging.error("name '' is not defined.")
except NotImplementedError:
    print("NotImplementedError is raised by abstract methods.")
except UnboundLocalError:
    print(
        '''Unbound Local Error is raised when a reference is made to a local variable in a function
        or method but no value has been bound to that variable.''')
except UnicodeError:
    print("Unicode Error. Unicode-related encoding or decoding error occurred")
"""