#!/bin/bash
curl -L \
-X POST \
-H "Accept: application/vnd.github+json" \
-H "Authorization: Bearer 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" \
-H "X-Github-Api-Version: 2022-11-28" \
https://api.github.com/repos/isdapps/IT-Security-Test/issues/issue_number/comments \
-d '{"body":"Last Observed" + last_observed_timestamp}'

