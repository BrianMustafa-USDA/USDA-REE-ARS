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
"""
def verify_duplicates_of_unique_ids(list):
    # Compare list to issues in isd repo using title
    dupl_list = []
    dupl_count = 0
    uniq_list = []
    for each_issue in list:
        if each_issue not in uniq_list:
            uniq_list.append(each_issue)  # Append each new non-duplicate unique issue to uniq_list
        else:
            dupl_list.append(each_issue)  # Capture each duplicate unique id in dupl_list
            dupl_count += 1  # Incremental count by 1

    print("(log4shell) dupl_list: ", dupl_list)
    print("(log4shell) uniq_list: ", uniq_list)
    print("Total # of duplicates: ", dupl_count)
    
    return dupl_list
"""

def log4shell_create_unique_ids_list(list):
    print("\nUnique IDs (Log4shell): ")
    print("Length of Log4Shell list: ", len(list))
    log4shell_unique_ids_list = []
    #assigned_unique_ids_list = []
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

        # Create list of all unique ids entitled 'log4shell_unique_ids_list'
        log4shell_unique_ids_list.append(unique_id)

        #dupl_uniq_ids_list = verify_duplicates_of_unique_ids(log4shell_unique_ids_list)

    return log4shell_unique_ids_list
    """
        print("unique_id, list[row]: ", unique_id, list[row])
        assigned_pair_unique_id = [unique_id, list[row]]
        print("Assigned_unique_ids_list (assigned values): ", assigned_pair_unique_id)
        assigned_unique_ids_list.append(assigned_pair_unique_id)

    return assigned_unique_ids_list
    """

"""
def get_all_repo_issues():
    try:
        exit_code = subprocess.run(["python3", "get_github_issues.py"])
        print(exit_code)
    except FileNotFoundError as exc:
        print(f"Process failed because the executable could not be found.\n{exc}")
    except subprocess.CalledProcessError as exc:
        print(
            f"Process failed because did not return a successful return code. "
            f"Returned {exc.returncode}\n{exc}"
        )
    except subprocess.TimeoutExpired as exc:
        print(f"Process timed out.\n{exc}")
"""
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
        session.auth = (owner, BEARER_KEY)
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

# Get all issues from the github repo and return the result in JSON.
def get_github_issues():

    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE,
    }

    per_page = {GITHUB_PER_PAGE: GITHUB_MAX_LIMIT_PER_PAGE}
    print("printing per_page: ", per_page)
    # print("Headers:", headers)

    print("GITHUB_API_URL", GITHUB_API_URL)
    print("type of GITHUB_API_URL", type(GITHUB_API_URL))
    print("before passing url to .get(): ", GET_URL)
    print("str(GET_URL: ", str(GET_URL))
    # Make a GET request and assign API data to variable entitled 'response'
    response = requests.get(GET_URL, headers=headers, params=per_page)

    print("Request URL:", response.url)
    print("Return Code:", response.status_code)

    # print("Return json:", response.json())

    # return JSON content of response
    return response.json()

def get_issue_titles(issues):
    # Initialize the dictionary to store the issue number and title

    issue_titles = {}

    for issue in issues:
        # Filter out any pull requests, which happen to be open issues.
        if not "pull_request" in issue:
            # print(issue['number'])
            # print(issue['title'])
            issue_number = issue['number']
            issue_title = issue['title']
            issue_titles[issue_number] = issue_title
    return issue_titles

def get_issue_number():
    # Retrieve an issue on api.github.com using the given parameters.
    # Our url to create API response

    #url = "https://api.github.com/repos/%s/%s/issues" % (owner, repo)
    url = "https://api.github.com/repos/%s/%s/issues" % (owner, repo)

    # Create headers to get issues from isd/apps repository
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": "token %s" % config['global-config-variables']['BEARER_KEY'],
        "X-GitHub-Api-Version": "2022-11-28",
    }
    #headers = {'Authorization': personal_access_token}
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

def get_last_observed_timestamp(uniq_id, list):
    # for each
    #print("list: ", list)
    last_observed_timestamp = ""
    for row in list:
        # create a list unique_id by pulling same components from list

        #print("row", row)

        list_uniq_id = str(row[0]) + unique_id_title_delimiter + row[1] + unique_id_title_delimiter + str(row[3]) + unique_id_title_delimiter + str(row[4]) + unique_id_title_delimiter + row[12]
        #print(list_uniq_id)


        # create list uniq id from components of list row
        if uniq_id == list_uniq_id:
            last_observed_timestamp = row[12]

        # if uniq id == list uniq_id

        # Last Observed Timestamp
        # list[row][12] -> Column: Last Observed
            #print("last_observed_timestamp: ", last_observed_timestamp)
            return last_observed_timestamp

"""
def create_most_recent_timestamp_commment_for_duplicate_issue(issue_number):

    # URL to create github issues
    url = "https://api.github.com/repos/%s/%s/issues/%s/comments" % (owner, repo, issue_number)
    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE,
    }

    r = requests.post(url, headers=headers)

    if r.status_code == 200:
        data = json.load(r.text)
    else:
        print("Error")
"""
#def create_most_recent_timestamp_comment_of_duplicate_issue(title, labels=None, assignees=None, body=None):
def create_most_recent_timestamp_comment_for_existing_issue(owner, repo, issue_number, last_observed_timestamp):
    """
    # Create an issue comment with most recent timestamp for each existing duplicate issue in repo
    try:
       #subprocess.run(["/home/brian.mustafa/"], timeout=10, check=True)
       exit_code = subprocess.run(["bash", "-x", "c.sh"], timeout=10, check=True)
       print(exit_code)
    except FileNotFoundError as exc:
        print(f"Process failed because the executable could not be found.\n{exc}")
    except subprocess.CalledProcessError as exc:
        print(
            f"Process failed because did not return a successful return code. "
            f"Returned {exc.returncode}\n{exc}"
        )
    except subprocess.TimeoutExpired as exc:
        print(f"Process timed out.\n{exc}")
    """

    # Our url to create issue comments via POST
    url = "https://api.github.com/repos/%s/%s/issues/%s/comments" % (owner, repo, issue_number)

    # Display message in log file of logging into repo
    logging.info("Logging into repo %s" % repo)
    # Create an authenticated session to create the issue in security report
    with requests.Session() as session:
        session = requests.Session()
        session.auth = (owner, BEARER_KEY)
    try:
        session.post(url)
        logging.info("Successfully created session")
    except ConnectionError as ce:
        print(ce)
        logging.error("Connection Error")

    # create issue comment of duplicate
    duplicate_issue_comment = {
f'### body': f'Last Created: {last_observed_timestamp}'
    }
    # Add issue comment of most recent duplicate issues to previously created issue in our repository
    new_repo = session.post(url, json.dumps(duplicate_issue_comment))
    print("new_repo: ", new_repo)
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
    for uniq_id in uniq_ids_list:
        print("values - issue_titles")
        print(uniq_id)
        for issue_value in issue_titles.values():
            print("uniq_id in list: ", uniq_id)
            # Check that issue_titles.values() contains correct values
            print("inside issue_title: ", issue_value)
            if uniq_id == issue_value:
                flag = True
                print("flag is True", flag)
                print("Github issue already exists in repo")
                print("uniq_id: ", uniq_id)
                print("issue_value: ", issue_value)
                last_observed_timestamp = get_last_observed_timestamp(uniq_id, log4shell_no_header_issues_list)
                print("last_observed_timestamp: ", last_observed_timestamp)
                # Get most recent issue number from each duplicate unique id on this list
                # pass the issue_number into create_most_recent_timestamp_comment_of_duplicate_issues()
                issue_number = get_issue_number()
                print("returned issue number: ", issue_number)
                continue
                """
                # check if flag is true
                if flag:
                    print("The issue already exists")
                    dupl_unique_ids_list.append(uniq_id, issue_number)
                    create_most_recent_timestamp_comment_for_existing_issue(owner, repo, issue_number,
                                                                            last_observed_timestamp)
                else:
                    print("New issue.")
                """

            else:
                print("New issue in repo")

        # check if flag is True
        if flag:
            # if issue exists, then send an API call
            print("The issue already exists")
            # Follow same format
            dupl_unique_ids_list.append(uniq_id)
            # create most recent timestamp comment for existing issue
            create_most_recent_timestamp_comment_for_existing_issue(owner, repo, issue_number,last_observed_timestamp)
            # reset flag to false
            flag = False
            # for each issue, make sure flag is set to false
            # drop into if condition, sets it to true
            # if the flag is true, then after creating comment for github issue
        else:
            print("New issue")

            # At some point, reset flag to false
            # Only after creating most recent timestamp comment

            # return list with issue_number, a flag of whether issue_number is new (0 is new, 1 exists) & last_observed_timestamp
            return dupl_unique_ids_list
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
    session.auth = (owner, BEARER_KEY)

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
    session.auth = (owner, BEARER_KEY)

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

# Assign owner of [user] from security_reports_issues_scraper.conf
owner = config["user"]["owner"]

# Assign repo of [user] from security_reports_issues_scraper.conf
repo = config["user"]["repo"]

# Assign personal_access_token within [API] in security_reports_issues_scraper.conf
BEARER_KEY = config["global-config-variables"]["BEARER_KEY"]

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
GITHUB_MAX_LIMIT_PER_PAGE = int(config["local-config-variables"]["GITHUB_MAX_LIMIT_PER_PAGE"])
GET_URL = GITHUB_API_URL + '/' + GITHUB_REPO + '/' + GITHUB_API_TYPE
print("url of github issues - GET_URL: ", GET_URL)
print("Type of URL: ", type(GET_URL))
print("str of GET_URL", str(GET_URL))
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
logging.info("Checking if security report <%s> exists." % log4shell_report)
    if log4shell_report:
        logging.info("Security Report <%s> exists." % log4shell_report)
    else:
        logging.error("FileNotFoundError. Security Report <%s> does not exist." % log4shell_report)
"""

# Starting security_reports_issues_scraper.py
logging.info("Successfully started execution of <security_reports_issues_scraper.py>")

# Enter Github Login Credential
github = login(owner, BEARER_KEY)

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
print("!Issue titles:", issue_titles)

# return list of issue titles whether issues is new or already exists,
    #if issue already exists, create loop to iterate through that list, then create comment on that issue
dupl_unique_ids_list = verify_duplicates_of_github_issues(issue_titles, log4shell_unique_ids_list)
print("dupl_unique_ids_list: ", dupl_unique_ids_list)

# Iterate through unique identifiers to pass each issue
# into Log4Shell_create_github_issue() function
print("\nCreate issues from Log4Shell Report: ")

# Iterate and create each issue in "Log4Shell_Weekly NAL (On Prem + Azure + Agents) Vulnerability Report - CHML Vulns  7 Days.csv> exists."
# onto the repo

for issue in range(len(log4shell_unique_ids_list)):
    print("(1)Issue in log4shell_no_dupl_all_issues_list")
    print(issue)
    unique_id = log4shell_unique_ids_list[issue][0]
    #dupl_list = verify_duplicates(unique_id)
    print("Log4Shell Unique_id: ", log4shell_unique_ids_list)
    print("New Unique_ids_list")
    unique_ids_list = log4shell_unique_ids_list[issue][1]
    print("Unique_ids_list: ", unique_ids_list)

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
"""
logging.info('Complete Logging')

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
    print(
        '''Unbound Local Error is raised when a reference is made to a local variable in a function
        or method but no value has been bound to that variable.''')
except UnicodeError:
    print("Unicode Error. Unicode-related encoding or decoding error occurred")
"""
