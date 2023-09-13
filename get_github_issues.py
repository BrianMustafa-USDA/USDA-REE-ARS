# Global config variables
BEARER_KEY = "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"
GITHUB_API_DATE = "2022-11-28"
GITHUB_API_URL = "https://api.github.com/repos"
GITHUB_REPO = "isdapps/IT-Security-Test"
GITHUB_API_TYPE = "issues"
GET_URL = GITHUB_API_URL + '/' + GITHUB_REPO + '/' + GITHUB_API_TYPE

# Get all issues from the github repo and return the result in JSON.
def get_github_issues():

    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE,
    }

    #print("Headers:", headers)

    response = requests.get(GET_URL, headers=headers)
import requests
import json

# Global config variables
BEARER_KEY = "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"
GITHUB_API_DATE = "2022-11-28"
GITHUB_API_URL = "https://api.github.com/repos"
GITHUB_REPO = "isdapps/IT-Security-Test"
GITHUB_API_TYPE = "issues"
GET_URL = GITHUB_API_URL + '/' + GITHUB_REPO + '/' + GITHUB_API_TYPE

# Get all issues from the github repo and return the result in JSON.
def get_github_issues():

    headers = {
        'Accept': 'application/vnd.github+json',
        'Authorization': 'Bearer ' + BEARER_KEY,
        'X-GitHub-Api-Version': GITHUB_API_DATE,
    }

    #print("Headers:", headers)

    response = requests.get(GET_URL, headers=headers)

    #print("Request URL:", response.url)
    #print("Return Code:", response.status_code)

    #print("Return json:", response.json())

    return response.json()


def get_issue_titles(issues):
    # Initialize the dictionary to store the issue number and title
    issue_titles = {}

    for issue in issues:
        #print(issue['number'])
        #print(issue['title'])
        issue_number = issue['number']
        issue_title = issue['title']
        issue_titles[issue_number] = issue_title

    return issue_titles


# Main program

issues = get_github_issues()
print(json.dumps(issues, indent = 4, sort_keys= True))

issue_titles = get_issue_titles(issues)
print("Issue titles:", issue_titles)


