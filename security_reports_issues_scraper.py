# Standard Python libraries
import configparser
import csv
import json
import logging
import requests
import time

# Custom Library:
# Source URL: https://github3.readthedocs.io/en/latest/
from github3 import login

# Initializing Basic Configuration File entitled "security_reports_issues_scraper_202303"
logging.basicConfig(filename="security_reports_issues_scraper_202308_test_case_1.log",
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

"""
Create log4shell_create_unique_ids() function to 
pass list object "list" of unique identifier fields
in order to parse and create unique identifiers from "Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv"
"""

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

        # Append each unique id to list of all unique ids in csv report entitled 'log4shell_unique_ids_list'
        print("unique_id, list[row]: ", unique_id, list[row])
        assigned_pair_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ", assigned_pair_unique_id)
        assigned_unique_ids_list.append(assigned_pair_unique_id)

    return assigned_unique_ids_list

"""
Create weekly_nal_create_unique_ids() function to pass list object  
to create unique identifiers from "Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv"
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

        # Append each unique to list of all unique ids in csv report entitled 'weekly_nal_unique_ids_list'
        weekly_nal_unique_ids_list.append(unique_id)

    return weekly_nal_unique_ids_list
    """
        assigned_pair_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(assigned_pair_unique_id)
    print("list of assigned unique ids:")
    print(assigned_unique_ids_list)
    
    return assigned_unique_ids_list
    """
"""
Create ars_bod_create_unique_ids() function to 
pass list object "list" to create unique identifiers from "ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan Report.csv"
"""

def ars_bod_create_unique_id(list):
    print("\nUnique IDs: ")
    print("Length of list: ", len(list))
    ars_bod_unique_ids_list = []
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

        # Append each unique to list of all unique ids in csv report entitled 'ars_bod_unique_ids_list'
        ars_bod_unique_ids_list.append(unique_id)
    return ars_bod_unique_ids_list
    """
        pair_assigned_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ")
        assigned_unique_ids_list.append(pair_assigned_unique_id)
    return assigned_unique_ids_list
    """
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

def log4shell_create_github_issue(title, labels, body):
    # Display message to log file to indicate program is connecting into https://api.github.com
    logging.info("""Connecting into https://api.github.com in order to create issue on 
    <Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv>""")

    # Create dict of headers in order to create new issues via POST
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE
    }

    # Create an issue on https://api.github.com using the given parameters.
    # Our url to create issue comments via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (OWNER, REPO)

    # Display message in log file of logging into REPO
    logging.info("Logging into REPO <%s>" % REPO)

    """
    # Create an authenticated session to create the issue from the security report (.csv)
    session = requests.Session()
    session.auth = (OWNER, BEARER_KEY)
    """

    # for unique_id in Security_Report:
    # create dict for each issue entitled "log4shell_issue"
    log4shell_issue = {
        "title": title,  # assign title of unique_id to each new issue
        "labels": labels,
        "body": body
    }
    print("log4shell_issue JSON:", json.dumps(log4shell_issue, indent=4, sort_keys=True))
    print("log4shell_issue: ", log4shell_issue)
    print("type: ", type(log4shell_issue))
    # Add the issue to our repository via POST
    new_repo = requests.post(POST_URL, headers=headers, data=json.dumps(log4shell_issue))
    #exit()
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

# Get all issues from REPO and return the result in JSON.
def get_github_issues():

    # Create dict of headers
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE
    }
    print("GITHUB_API_URL", GITHUB_API_URL)

    # Make a GET request and assurl of github issues - GET_URLign API data to variable entitled 'response'
    response = requests.get(GET_URL, headers=headers)

    print("Request URL:", response.url)
    print("Return Code:", response.status_code)
    # return JSON content of response
    return response.json()

# GET issue titles for all issues on REPO
def get_issue_titles(issues):
    # Initialize the dictionary to store the issue number and title
    issue_titles = {}

    for issue in issues:
        # Filter out any pull requests, which happen to be open issues.
        if not "pull_request" in issue:
            issue_number = issue['number']
            print("issue number", issue_number)
            issue_title = issue['title']
            issue_titles[issue_number] = issue_title
    return issue_titles

def get_issue_number():

    # Create dict of headers in order to create new issues via POST
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE
    }

    # Our url to create API response

    url = "https://api.github.com/repos/%s/%s/issues" % (OWNER, REPO)

    print("get an issue's response content")
    r = requests.get(url, headers=headers)

    print("r.text:", r.text)
    print("r.status_code", r.status_code)

    if r.status_code == 200:
        # get JSON object from the response by calling r.text
        data = json.loads(r.text)
        print("data type: ", type(data))
        print("data: ", data)
        """
        for key, value in data[0]:
            print("key" + key)
            print("value" + value)
        """
        print("data[0]: ", data[0])

        # Extract value of issue
        for key in data[0]:
            if key == 'number':
                print("data[0]key:  ")
                print(data[0][key])
                issue_number = data[0][key]

        for i in data:
            value = data[0]
            print("Key and value pair ({}) = ({})".format(i, value))

        """
        i = 'number'
        for i in data:
            print("data['issue number']")
            issue_number = data['number']
            print(issue_number)
        """
    else:
        print("Error:", r.status_code)
    return issue_number

# create function to get last observed timestamp
def get_last_observed_timestamp(uniq_id_pair_list, list):
    #print("list: ", list)
    last_observed_timestamp = ""
    for row in list:
        # create a list unique_id by pulling same components from list

        print("row: ", row)

        list_uniq_id = str(row[0]) + unique_id_title_delimiter + row[1] + unique_id_title_delimiter + str(row[3]) + unique_id_title_delimiter + str(row[4]) + unique_id_title_delimiter + row[12]
        print("list_uniq_id: ", list_uniq_id)


        # create list uniq id from components of list row
        print("uniq_id_pair: ", uniq_id_pair_list
        print(type(uniq_id_pair_list))

        # compare uniqie id from uniq_id_pair_list to list_uniq_id
        if uniq_id_pair_list[0] == list_uniq_id:
            last_observed_timestamp = row[12]

        # Last Observed Timestamp
        # list[row][12] -> Column: Last Observed
            #print("last_observed_timestamp: ", last_observed_timestamp)
        return last_observed_timestamp

def create_issue_comment_of_most_updated_timestamp(OWNER, repo, issue_number, last_observed_timestamp):
    # Create dict of headers in order to create issue comment of most recent timestamp
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE,
    }

    # Our url to create issue comments via POST
    url = "https://api.github.com/repos/%s/%s/issues/%s/comments" % (OWNER, repo, issue_number)

    # Display message in log file of logging into REPO
    logging.info("Logging into REPO %s" % repo)

    # create issue comment of duplicate
    issue_comment = {
        'body': f'### Last Created: {last_observed_timestamp}'
    }
    # Add issue comment of most recent duplicate issues to previously created issue in our repository
    new_issue_comment = requests.post(url, data=json.dumps(issue_comment), headers=headers)
    if new_issue_comment == 201:
        print('Successfully Created Issue Comment for Issue {0}'.format(issue_number))
        logging.info('Successfully Created Issue for Issue {0}'. format(issue_number))
    else:
        print('Could not create Issue Comment for Issue {0}'.format(issue_number))
        print("new_issue_comment.content ", new_issue_comment.content)
        print("(type) new_issue_comment.content ", type(new_issue_comment.content))
        print('Response: ',  new_issue_comment.content)
        logging.error('Could not create Issue Comment for Issue {0}'.format(issue_number))
        logging.error('Response: {0},'.format(new_issue_comment.content))
    """
        if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
        logging.info('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)
        logging.error('Could not create Issue {0:s}'.format(title))
        logging.error('Response: ', new_repo.content)
    """

"""
create a function to add a new comment "last observed" field of new duplicate issue
"""

def verify_duplicates_of_github_issues(issue_titles, uniq_ids_list):
    dupl_unique_ids_list = []
    flag = False
    print("sample of unique_ids_list", uniq_ids_list)
    print("sample of issue titles: ", issue_titles)

    print("Issue_titles of log4shell csv:")
    # Iterate through values of issue_titles
    for uniq_id_pair in uniq_ids_list:
        print("values - issue_titles")
        print("uniq_id title", uniq_id_pair_list[0])
        print("uniq_id components", uniq_id_pair_list[1])
        for issue_value in issue_titles.values():
            print("uniq_id_pair_list in list: ", uniq_id_pair_list)
            # Check that issue_titles.values() contains correct values
            print("issue_value ", issue_value)
            # Create conditional to verify uniq_id_pair_list[0], the unique identifier, is equal to issue_value
            if uniq_id_pair_list[0] == issue_value:
                flag = True
                print("flag is True", flag)
                print("Github issue already exists in REPO")
                print("uniq_id_pair_list: ", uniq_id_pair_list)
                print("type of uniq_id_pair: ", type(uniq_id_pair_list))
                print("issue_value: ", issue_value)
                last_observed_timestamp = get_last_observed_timestamp(uniq_id_pair_list, log4shell_no_header_issues_list)
                print("last_observed_timestamp: ", last_observed_timestamp)
                # Get most recent issue number from each duplicate unique id on this list
                # pass the issue_number into create_issue_comment_of_most_updated_timestamp()
                issue_number = get_issue_number()
                print("returned issue number: ", issue_number)
                continue
                """
                # check if flag is true
                if flag:
                    print("The issue already exists")
                    dupl_unique_ids_list.append(uniq_id, issue_number)
                    create_issue_comment_of_most_updated_timestamp(OWNER, REPO, issue_number,
                                                                            last_observed_timestamp)
                else:
                    print("New issue.")
                """
            else:
                print("New issue in repo")

        # check if flag is true
        if flag:
            # if issue exists, then send an API call to GitHub
            print("The issue already exists")
            # follow same format
            dupl_unique_ids_list.append(uniq_id)
            # create most recent timestamp comment for existing issue on repo
            create_issue_comment_of_most_updated_timestamp(OWNER, REPO, issue_number, last_observed_timestamp)
            # reset flag to false
            flag = False
            # for each issue, make sure flag is set to false
            # drop into if condition, sets it to true
            # if the flag is true, then after creating comment for github issue
        else:
            print("New issue")
            # return list with issue_number, a flag of whether issue_number is new (0 is new, 1 exists) & last_observed_timestamp
    return dupl_unique_ids_list

def weekly_nal_create_github_issue(
        title, labels=None,
        assignees=None, body=None):
    # Display message to log file to indicate program is connecting into https://api.github.com
    logging.info("""Connecting into https://api.github.com in order to create issue on 
        <Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv>""")

    # Create dict of headers in order to create new issues via POST
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE
    }

    # Our url to create issues via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (OWNER, REPO)

    """
    # Create an authenticated session to create the issue from the security report (.csv)
    session = requests.Session()
    session.auth = (OWNER, BEARER_KEY)
    """

    # Create new issues for Weekly NAL Report
    weekly_nal_issue = {
        'title': title,  # assign each new issue to title
        'labels': labels,
        'assignees': assignees,
        'unique_id_body':
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
    # Add the issue to our repository via POST
    new_repo = requests.post(url, data=json.dumps(weekly_nal_issue), headers=headers)

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

    # Create dict of headers in order to create new issues via POST
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE
    }

    # Our url to create issues via POST
    url = "https://api.github.com/repos/%s/%s/issues" % (OWNER, REPO)

    """
    # Create an authenticated session to create the issue from the security report (.csv)    
    session = requests.Session()    
    session.auth = (OWNER, BEARER_KEY)    
    """

    # Create new issues for security report (.csv)
    ars_bod_issue = {
        'title': title,  # assign each new issue to title
        'labels': labels,
        'assignees': assignees,
        'unique_id_body':
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
    # Add the issue to our repository via POST
    new_repo = requests.post(url, data=json.dumps(ars_bod_issue), headers=headers)

    if new_repo.status_code == 201:
        print('Successfully Created Issue {0:s}'.format(title))
        logging.info('Successfully Created Issue {0:s}'.format(title))
    else:
        print('Could not create Issue {0:s}'.format(title))
        print('Response: ', new_repo.content)
        logging.error('Could not create Issue {0:s}'.format(title))
        logging.error('Response: ', new_repo.content)

# Remove header (1st row) of each .csv report
def remove_header(list):
    list.pop(0)
    return list

def delay_api_requests():
    delay_in_sec = int(config['API']['delay'])
    time.sleep(delay_in_sec)

# Create and assign ConfigParser Object to retrieve configuration data from config.ini
config = configparser.ConfigParser()

# Read config file entitled "security_reports_issue_scraper.conf"
config.read("security_reports_issues_scraper.conf")

# Assign OWNER of [user] from security_reports_issues_scraper.conf
OWNER = config["user"]["OWNER"]

# Assign REPO of [user] from security_reports_issues_scraper.conf
REPO = config["user"]["REPO"]

# Assign delimiter within [unique-id-title] in security_reports_issues_scraper.conf
unique_id_title_delimiter = config["unique-id-title"]["delimiter"]

# Global config variables
BEARER_KEY = config["global-config-variables"]["BEARER_KEY"]
GITHUB_API_DATE = config["global-config-variables"]["GITHUB_API_DATE"]

# local config variables
GITHUB_API_URL = config["local-config-variables"]["GITHUB_API_URL"]
GITHUB_REPO = config["local-config-variables"]["GITHUB_REPO"]
GITHUB_API_TYPE = config["local-config-variables"]["GITHUB_API_TYPE"]
GITHUB_PER_PAGE = config["local-config-variables"]["GITHUB_PER_PAGE"]
GET_URL = GITHUB_API_URL + '/' + GITHUB_REPO + '/' + GITHUB_API_TYPE + '?' + GITHUB_PER_PAGE
POST_URL = GITHUB_API_URL + '/' + GITHUB_REPO + '/' + GITHUB_API_TYPE
print("url of github issues - GET_URL: ", GET_URL)
print("Type of URL: ", type(GET_URL))
print("str of GET_URL", str(GET_URL))

"""
Create hash object from "config file." configuration file
to read in weekly security report related to "Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report
- CHML Vulns  7 Days.csv"
"""

log4shell_report = config['security-csv-reports']['Log4Shell_report']

logging.info("Checking if security report <%s> exists." % log4shell_report)
if log4shell_report:
    logging.info("Security Report <%s> exists." % log4shell_report)
else:
    logging.error("Security Report <%s> does not exist." % log4shell_report)


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
github = login(OWNER, BEARER_KEY)

"""
if github == login(OWNER, personal_access_token):
    logging.info("Successfully logged into REPO <isdapps/IT-Security-Test>.")
else:
    logging.error("Unable to log into REPO <isdapps/IT-Security-Test> using current login credentials.")
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

print("test of log4shell_issues_list: ", log4shell_issues_list)
log4shell_no_header_issues_list = remove_header(log4shell_issues_list)
print("No header list: ", log4shell_no_header_issues_list)
# print length of all issues of Log4Shell security report without header
print("\n(No header) Total Number of issues: ", len(log4shell_no_header_issues_list))
print("Type of log4shell_no_header_issues_list: ", type(log4shell_no_header_issues_list))

"""
for issue in range(len(log4shell_no_header_issues_list)):
    print(log4shell_no_header_issues_list[issue])
"""

#log4shell_no_dupl_all_issues_list = verify_duplicates(log4shell_no_header_issues_list)

print("verified log4shell_issues")

# create unique ids for each issue in the security report
log4shell_unique_ids_list = log4shell_create_unique_ids_list(log4shell_no_header_issues_list)

# log4shell unique ids list
#print("try log4shell_no_dupl_all_unique_ids_list: ", log4shell_no_dupl_all_unique_ids_list)
print("unique id titles of Log4shell_unique_ids_list: ", log4shell_unique_ids_list)
print("Len of log4shell_unique_ids_list: ", len(log4shell_unique_ids_list))

issues = get_github_issues()
# print the content of response object in JSON format
print("output of issues", issues)
# Execute json.dumps to convert and serialize all github issues into JSON string
print(json.dumps(issues, indent=4, sort_keys=True))

issue_titles = get_issue_titles(issues)
# print issue_titles
print("Issue titles: ", issue_titles)

# return list of issue titles whether issues is new or already exists,
#if issue already exists, create loop to iterate through that list, then create comment on that issue
dupl_unique_ids_list = verify_duplicates_of_github_issues(issue_titles, log4shell_unique_ids_list)
print("dupl_unique_ids_list: ", dupl_unique_ids_list)

# Iterate through unique identifiers to pass each issue
# into Log4Shell_create_github_issue() function
print("\nCreate issues from Log4Shell Report: ")

"""
Iterate and create each issue in 
"Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> exists."
onto the REPO
"""

# if unique_ids is empty, then take every issue in for loop you have
# populate the issue into GitHub

for issue in range(len(log4shell_unique_ids_list)):
    print("Issue in log4shell_no_dupl_all_issues_list")
    print(issue)
    unique_id_title = log4shell_unique_ids_list[issue][0]
    print("unique_id_title: ", unique_id_title)
    #if unique_id_title in issue_titles:
        # update the comment because the title already exists
        # create_issue_comment_of_most_updated_timestamp()
        # last_discovered_timestamp
    # else: grab the rest of information from unique_ids_list to create new issue
    unique_id_list = log4shell_unique_ids_list[issue][1]
    #print("Log4Shell Unique_id: ", log4shell_unique_ids_list)
    print("#Unique_id_list: ", unique_id_list)
    unique_id_labels = ["Test Label"]
    unique_id_body = f'### Plugin: {unique_id_list[0]}\n'
    unique_id_body += f'### Plugin Name: {unique_id_list[1]}\n'
    unique_id_body += f'### Severity: {unique_id_list[2]}\n'
    unique_id_body += f'### IP Address: {unique_id_list[3]}\n'
    unique_id_body += f'### Port: {unique_id_list[4]}\n'
    unique_id_body += f'### DNS Name: {unique_id_list[5]}\n'
    unique_id_body += f'### NetBIOS Name: {unique_id_list[6]}\n'
    unique_id_body += f'### Plugin Output: {unique_id_list[7]}\n'
    unique_id_body += f'### Solution: {unique_id_list[8]}\n'
    unique_id_body += f'### CVSS V3 Base Score: {unique_id_list[9]}\n'
    unique_id_body += f'### CVE: {unique_id_list[10]}\n'
    unique_id_body += f'### First Discovered: {unique_id_list[11]}\n'
    unique_id_body += f'### Last Discovered: {unique_id_list[12]}'
    print("Body:", unique_id_body)
    delay_api_requests()
    log4shell_create_github_issue(unique_id_title, unique_id_labels, unique_id_body)

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
weekly_nal_no_dupl_all_issues_list = verify_duplicates_of_github_issues(weekly_nal_no_header_issues_list)
print("weekly_nal_no_dupl_all_issues_list")
print(weekly_nal_no_dupl_all_issues_list)
# Weekly_nal_create_unique_ids
# weekly_nal_no_dupl_all_issues_list = weekly_nal_create_unique_id(weekly_nal_no_dupl_all_issues_list)

"""
#Iterate through unique identifiers (no duplicates) to pass each issue
#into Weekly_NAL_create_github_issue() function
"""
print("\n\nCreate issues from Weekly NAL Report: ")

for issue in range(len(weekly_nal_no_dupl_all_issues_list)):
    unique_id = weekly_nal_no_dupl_all_issues_list[issue][0]
    unique_ids_list = weekly_nal_no_dupl_all_issues_list[issue][1]
    print("(Weekly NAL Report) Unique IDs List")
    print(unique_ids_list)
    print(weekly_nal_no_dupl_all_issues_list[issue][1][0])
    delay_api_requests()
    #weekly_nal_create_github_issue(unique_id, ["Test Label"], ["brian-mustafa"], unique_ids_list)
"""

"""
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
"""
"""
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
    print("Unbound Local Error is raised when a reference is made to a local variable in a function or method but no value has been bound to that variable.")
except UnicodeError:
    print("Unicode Error. Unicode-related encoding or decoding error occurred")
"""
