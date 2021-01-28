# snyk-container-remediation

Find the latest version that fixes all vulns per package,
similar to remediation advice for open source dependency projects

### with CLI output 
`snyk test --json | go run main.go --cli`

`cat cli-json-output.json | go run main.go --cli`

### with API output 
`cat api-aggregated-issues-output.json | go run main.go --api`
