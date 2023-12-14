# Standard Python libraries
import csv
import json
import logging
import os
import requests
import time

# Custom Library:
# Source URL: https://github3.readthedocs.io/en/latest/
from github3 import login
# Import load_dotenv to print variables of "security_reports_issues_scraper.env"
from dotenv import load_dotenv, dotenv_values

# from secureconfig import SecureConfigParser

# Initializing Basic Configuration File entitled "security_reports_issues_scraper_202303"
logging.basicConfig(filename="security_reports_issues_scraper_202308_test_case_1.log",
                    level=logging.DEBUG,
                    format="%(asctime)s %(levelname)s %(message)s",
                    datefmt="%m/%d/%Y %H:%M:%S")

logging.info("Start Logging")

"""
# Create and assign ConfigParser Object to retrieve configuration data from config.ini
config = configparser.ConfigParser()

"""
config = {
    **dotenv_values(".env.shared"),  # load shared development variables
    **dotenv_values(".env.secret"),  # load sensitive variables
    **os.environ,  # override loaded values w/ environment variables
}

print("config: ", config)

# Assign OWNER of ["USER"] from security_reports_issues_scraper.conf
OWNER = config['OWNER']

# Assign REPO of [user] from security_reports_issues_scraper.conf
REPO = config['REPO']

# Assign delimiter within security_reports_issues_scraper.conf
UNIQUE_ID_TITLE_DELIMITER = config['UNIQUE_ID_TITLE_DELIMITER']

# Global config variables
BEARER_KEY = config['BEARER_KEY']
GITHUB_API_DATE = config['GITHUB_API_DATE']

# local config variables
GITHUB_API_URL = config['GITHUB_API_URL']
GITHUB_REPO = config['GITHUB_REPO']
GITHUB_API_TYPE = config['GITHUB_API_TYPE']
GITHUB_PER_PAGE = config['GITHUB_PER_PAGE']
GET_URL = GITHUB_API_URL + '/' + GITHUB_REPO + '/' + GITHUB_API_TYPE + '?' + GITHUB_PER_PAGE
POST_URL = GITHUB_API_URL + '/' + GITHUB_REPO + '/' + GITHUB_API_TYPE
print("URL of github issues - GET_URL: ", GET_URL)
print("Type of URL: ", type(GET_URL))
print("str of GET_URL", str(GET_URL))

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
    assigned_pair_unique_ids_list = []
    for row in range(len(list)):
        '''
        unique_id created using unique fields from 5 columns assigned to each issue in Log4Shell report:
        list[row][0] -> Column: "Plugin"
        list[row][1] -> Column: "Plugin Name"
        list[row][3] -> Column: "IP Address"
        list[row][4] -> Column: "Port Number"
        list[row][11] -> Column: "First Discovered"
        '''

        unique_id = str(list[row][0]) + UNIQUE_ID_TITLE_DELIMITER + list[row][1] + UNIQUE_ID_TITLE_DELIMITER + str(
            list[row][3]) + UNIQUE_ID_TITLE_DELIMITER + str(list[row][4]) + UNIQUE_ID_TITLE_DELIMITER + list[row][11]

        print("Unique ID of log4shell_issues: ", unique_id)

        # Append each unique id to list of all unique ids in csv report entitled 'log4shell_unique_ids_list'
        print("unique_id, list[row]: ", unique_id, list[row])
        assigned_pair_unique_id = [unique_id, list[row]]
        print("Assigned_unique_id_list (assigned values): ", assigned_pair_unique_id)
        assigned_pair_unique_ids_list.append(assigned_pair_unique_id)

    return assigned_pair_unique_ids_list

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
        unique_id = str(list[row][0]) + DELIMITER + list[row][1] + DELIMITER + str(
            list[row][3]) + DELIMITER + str(list[row][4]) + DELIMITER + list[row][11]

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
        unique_id = str(list[row][0]) + DELIMITER + list[row][1] + DELIMITER + str(
            list[row][3]) + DELIMITER + str(list[row][4]) + DELIMITER + list[row][18]

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
        unique_id = str(list[row][0]) + UNIQUE_ID_TITLE_DELIMITER + list[row][1] + UNIQUE_ID_TITLE_DELIMITER + str(
            list[row][3]) + UNIQUE_ID_TITLE_DELIMITER + str(list[row][4]) + UNIQUE_ID_TITLE_DELIMITER + list[row][18]

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
    # exit()
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
    print('GITHUB_API_URL', GITHUB_API_URL)

    # Make a GET request and assure of github issues - GET_URL align API data to variable entitled 'response'
    print('GET_URL: ', GET_URL)
    response = requests.get(GET_URL, headers=headers)

    print('Request URL: ', response.url)
    print("Type of Request URL: ", type(response.url))
    print('Return Code: ', response.status_code)
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
def get_last_observed_timestamp(unique_id_title, list):
    # print("list: ", list)
    last_observed_timestamp = ""
    for row in list:
        # create a list unique_id by pulling same components from list
        print("row: ", row)

        unique_id = str(row[0]) + UNIQUE_ID_TITLE_DELIMITER + row[1] + UNIQUE_ID_TITLE_DELIMITER + str(
            row[3]) + UNIQUE_ID_TITLE_DELIMITER + str(row[4]) + UNIQUE_ID_TITLE_DELIMITER + row[12]
        print("unique_id: ", unique_id)

        # create unique_id from components of list row
        print("@uniq_ids_pair_list: ", unique_id_title)
        # compare unique id from uniq_id_pair_list to list_uniq_id
        if unique_id_title == unique_id:
            last_observed_timestamp = row[12]

        # Last Observed Timestamp
        # list[row][12] -> Column: Last Observed
        # print("last_observed_timestamp: ", last_observed_timestamp)
        return last_observed_timestamp


def create_issue_comment_of_most_updated_timestamp(OWNER, REPO, issue_number, last_observed_timestamp):
    # Create dict of headers in order to create issue comment of most recent timestamp
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE,
    }

    # Our url to create issue comments via POST
    url = "https://api.github.com/repos/%s/%s/issues/%s/comments" % (OWNER, REPO, issue_number)

    # Display message in log file of logging into REPO
    logging.info("Logging into REPO %s" % REPO)

    # create issue comment of duplicate
    issue_comment = {
        'body': f'### Last Created: {last_observed_timestamp}'
    }
    # Add issue comment of most recent duplicate issues to previously created issue in our repository
    new_issue_comment = requests.post(url, data=json.dumps(issue_comment), headers=headers)
    if new_issue_comment.status_code == 201:
        print('Successfully Created Issue Comment for Issue {0}'.format(issue_number))
        logging.info('Successfully Created Issue for Issue {0}'.format(issue_number))
    else:
        print('Could not create Issue Comment for Issue {0}'.format(issue_number))
        print("new_issue_comment.content ", new_issue_comment.content)
        print("(type) new_issue_comment.content ", type(new_issue_comment.content))
        print("new_issue_comment.status_code: ", new_issue_comment.status_code)
        print("new_issue_comment.reason: ", new_issue_comment.reason)
        print('Response: ', new_issue_comment.content)
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

def verify_duplicates_of_github_issues(issue_titles, unique_ids_list):
    dupl_unique_ids_list = []
    flag = False
    print("sample of unique_ids_list", unique_ids_list)
    print("sample of issue titles: ", issue_titles)

    print("Issue_titles of log4shell csv:")
    # Iterate through values of issue_titles
    for unique_id_pair_list in unique_ids_list:
        print("values - issue_titles ")
        print("unique_id_pair_list: ", unique_id_pair_list)
        print("unique_ids_list - title: ", unique_id_pair_list[0])
        unique_id_title = unique_id_pair_list[0]
        print("unique_ids_list - components: ", unique_ids_list[0][1])
        for issue_value in issue_titles.values():
            print("uniq_id_pair_list in list: ", unique_ids_list)
            # Check that issue_titles.values() contains correct values
            print("issue_value ", issue_value)
            # Create conditional to verify uniq_id_pair_list[0], the unique identifier, is equal to issue_value
            if unique_id_title == issue_value:
                flag = True
                print("flag is True", flag)
                print("Github issue already exists in REPO")
                print("uniq_ids_list: ", unique_ids_list)
                print("type of unique_ids_list: ", type(unique_ids_list))
                print("issue_value: ", issue_value)
                last_observed_timestamp = get_last_observed_timestamp(unique_id_title,
                                                                      log4shell_no_header_issues_list)
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
            # if issue exists, then send an API call to GitHub API
            print("The issue already exists")
            # Append unique_id_pair to dupl_unique_ids_list
            dupl_unique_ids_list.append(unique_id_pair_list)
            # create most recent timestamp comment for existing issue on repo
            # create_issue_comment_of_most_updated_timestamp(OWNER, REPO, issue_number, last_observed_timestamp)
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
            f'### Plugin: {uniq_ids_list[0]}'
            f'### Plugin Name: {uniq_ids_list[1]}'
            f'### Severity: {uniq_ids_list[2]}'
            f'### IP Address: {uniq_ids_list[3]}'
            f'### Port: {uniq_ids_list[4]}'
            f'### DNS Name: {uniq_ids_list[5]}'
            f'### NetBios Name: {uniq_ids_list[6]}'
            f'### Plugin Output: {uniq_ids_list[7]}'
            f'### Solution: {uniq_ids_list[8]}'
            f'### CVSS V3 Base Score: {uniq_ids_list[9]}'
            f'### CVE: {uniq_ids_list[10]}'
            f'### First Discovered: {uniq_ids_list[11]}'
            f'### Last Observed: {uniq_ids_list[12]}'
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
            f'### Plugin: {uniq_ids_list[0]}'
            f'### Plugin Name: {uniq_ids_list[1]}'
            f'### Family: {uniq_ids_list[2]}'
            f'### Severity: {uniq_ids_list[3]}'
            f'### IP Address: {uniq_ids_list[4]}'
            f'### Port: {uniq_ids_list[5]}'
            f'### MAC Address: {uniq_ids_list[6]}'
            f'### DNS Name: {uniq_ids_list[7]}'
            f'### NetBios Name: {uniq_ids_list[8]}'
            f'### Plugin Output: {uniq_ids_list[9]}'
            f'### Synopsis: {uniq_ids_list[10]}'
            f'### Description: {uniq_ids_list[11]}'
            f'### Solution: {uniq_ids_list[12]}'
            f'### Vulnerability Priority Rating: {uniq_ids_list[13]}'
            f'### CVSS V2 Base Score: {uniq_ids_list[14]}'
            f'### CVSS V3 Base Score: {uniq_ids_list[15]}'
            f'### CPE: {uniq_ids_list[16]}'
            f'### CVE: {uniq_ids_list[17]}'
            f'### First Discovered: {uniq_ids_list[18]}'
            f'### Last Observed: {uniq_ids_list[19]}'
            f'### Cross References: {uniq_ids_list[20]}'
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
    # Assign variable entitled DELAY of requests made to GitHub API
    DELAY = config['DELAY']
    delay_in_sec = int(DELAY)
    print("delay_in_sec", delay_in_sec)
    time.sleep(delay_in_sec)


"""
Create hash object from "config file." configuration file
to read in weekly security report related to "Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report
- CHML Vulns  7 Days.csv"
"""

# LOG4SHELL_REPORT = os.getenv('LOG4SHELL_REPORT')
LOG4SHELL_REPORT = config['LOG4SHELL_REPORT']

logging.info("Checking if security report <%s> exists." % LOG4SHELL_REPORT)
if LOG4SHELL_REPORT:
    logging.info("Security Report <%s> exists." % LOG4SHELL_REPORT)
else:
    logging.error("Security Report <%s> does not exist." % LOG4SHELL_REPORT)

"""
Create hash object from "config file." configuration file
to read in weekly csv security reports related to "Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML
Vulns  7 Days.csv"
"""
weekly_nal_report = config['WEEKLY_NAL_REPORT']
"""
Create hash object from "config file." configuration file
to read in weekly csv reports related to "ARS BOD 22-01 National Agricultural Library (NAL) On-Prem + Azure Scan
Report.csv"
"""
ars_bod_report = config['ARS_BOD_REPORT']

"""
logging.info("Checking if security report <%s> exists." % LOG4SHELL_REPORT)
    if LOG4SHELL_REPORT:
        logging.info("Security Report <%s> exists." % LOG4SHELL_REPORT)
    else:
        logging.error("FileNotFoundError. Security Report <%s> does not exist." % LOG4SHELL_REPORT)
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
logging.info("Checking if security report <%s> exists." % LOG4SHELL_REPORT)
if LOG4SHELL_REPORT:
    logging.info("Security Report <%s> exists." % LOG4SHELL_REPORT)
else:
    logging.error("Security Report <%s> does not exist." % LOG4SHELL_REPORT)
"""

"""
logging.info(
    "Processing Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> to create issues.")
"""
print("LOG4SHELL_REPORT: ", LOG4SHELL_REPORT)

log4shell_issues_list = []
log4shell_issues_list = log4shell_read_csv_report(LOG4SHELL_REPORT)

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

# log4shell_no_dupl_all_issues_list = verify_duplicates(log4shell_no_header_issues_list)

print("verified log4shell_issues")

# create unique ids for each issue in the security report
log4shell_unique_ids_list = log4shell_create_unique_ids_list(log4shell_no_header_issues_list)

# log4shell unique ids list
# print("try log4shell_no_dupl_all_unique_ids_list: ", log4shell_no_dupl_all_unique_ids_list)
print("unique id titles of Log4shell_unique_ids_list: ", log4shell_unique_ids_list)
print("Len of log4shell_unique_ids_list: ", len(log4shell_unique_ids_list))

issues = get_github_issues()
# print the content of response object in JSON format
print("output of issues", issues)
# Execute json.dumps to convert and serialize all GitHub issues into JSON string
print(json.dumps(issues, indent=4, sort_keys=True))

issue_titles = get_issue_titles(issues)
# print issue_titles
print("Issue titles: ", issue_titles)

# return list of issue titles whether any issues is new or already exists,
# if issue already exists, create loop to iterate through that list, then create comment on that issue
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
print("log4shell_unique_ids_list: ", log4shell_unique_ids_list)
for issue in range(len(log4shell_unique_ids_list)):
    print("Issue in log4shell_no_dupl_all_issues_list")
    print(issue)
    unique_id_title = log4shell_unique_ids_list[issue][0]
    print("unique_id_title: ", unique_id_title)
    print("issue_titles.values() ", issue_titles.values())
    if unique_id_title in issue_titles.values():
        # update the comment because the title already exists
        issue_number = get_issue_number()
        print("issue_number: ", issue_number)
        last_observed_timestamp = get_last_observed_timestamp(unique_id_title, log4shell_no_header_issues_list)
        print("last_observed_timestamp: ", last_observed_timestamp)
        # create_issue_comment_of_most_updated_timestamp()
        print("Create Issue Comment")
        create_issue_comment_of_most_updated_timestamp(OWNER, REPO, issue_number, last_observed_timestamp)
        # last_discovered_timestamp
    else:
        # grab the rest of information from unique_ids_list to create new issue
        unique_ids_list = log4shell_unique_ids_list[issue][1]
        print("#Unique_ids_list: ", unique_ids_list)
        unique_id_labels = ["Test Label"]
        unique_id_body = f'### Plugin: {unique_ids_list[0]}\n'
        unique_id_body += f'### Plugin Name: {unique_ids_list[1]}\n'
        unique_id_body += f'### Severity: {unique_ids_list[2]}\n'
        unique_id_body += f'### IP Address: {unique_ids_list[3]}\n'
        unique_id_body += f'### Port: {unique_ids_list[4]}\n'
        unique_id_body += f'### DNS Name: {unique_ids_list[5]}\n'
        unique_id_body += f'### NetBIOS Name: {unique_ids_list[6]}\n'
        unique_id_body += f'### Plugin Output: {unique_ids_list[7]}\n'
        unique_id_body += f'### Solution: {unique_ids_list[8]}\n'
        unique_id_body += f'### CVSS V3 Base Score: {unique_ids_list[9]}\n'
        unique_id_body += f'### CVE: {unique_ids_list[10]}\n'
        unique_id_body += f'### First Discovered: {unique_ids_list[11]}\n'
        unique_id_body += f'### Last Discovered: {unique_ids_list[12]}'
        print("Body:", unique_id_body)
        delay_api_requests()
        log4shell_create_github_issue(unique_id_title, unique_id_labels, unique_id_body)

exit()

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
# Iterate through unique identifiers (no duplicates) to pass each issue
# into Weekly_NAL_create_github_issue() function
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
