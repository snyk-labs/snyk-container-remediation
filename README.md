# snyk-container-remediation
[![Go Report Card](https://goreportcard.com/badge/github.com/snyk-tech-services/snyk-container-remediation)](https://goreportcard.com/report/github.com/snyk-tech-services/snyk-container-remediation)

Find the nearest version that fixes all vulns per package,
similar to remediation advice for open source dependency projects

### with CLI output 
`snyk test --json | go run main.go --cli`

`cat cli-json-output.json | go run main.go --cli`

### with API output 
`cat api-aggregated-issues-output.json | go run main.go --api`

### Sample output
```
{
  "upgrades": [
    {
      "PkgName": "p11-kit/libp11-kit0",
      "FarthestFixedInVersion": "0.23.15-2+deb10u1",
      "FixesVulns": [
        "SNYK-DEBIAN10-P11KIT-1050836",
        "SNYK-DEBIAN10-P11KIT-1050833",
        "SNYK-DEBIAN10-P11KIT-1050832"
      ]
    },
    {
      "PkgName": "openldap/libldap-2.4-2",
      "FarthestFixedInVersion": "2.4.47+dfsg-3+deb10u3",
      "FixesVulns": [
        "SNYK-DEBIAN10-OPENLDAP-1035359",
        "SNYK-DEBIAN10-OPENLDAP-1039835",
        "SNYK-DEBIAN10-OPENLDAP-1039832"
      ]
    },
    {
      "PkgName": "krb5/libkrb5-3",
      "FarthestFixedInVersion": "1.17-3+deb10u1",
      "FixesVulns": [
        "SNYK-DEBIAN10-KRB5-1037638"
      ]
    },
    {
      "PkgName": "curl",
      "FarthestFixedInVersion": "7.64.0-4+deb10u1",
      "FixesVulns": [
        "SNYK-DEBIAN10-CURL-466510",
        "SNYK-DEBIAN10-CURL-466509",
        "SNYK-DEBIAN10-CURL-358918",
        "SNYK-DEBIAN10-CURL-358856",
        "SNYK-DEBIAN10-CURL-358773",
        "SNYK-DEBIAN10-CURL-358763",
        "SNYK-DEBIAN10-CURL-358715",
        "SNYK-DEBIAN10-CURL-358701",
        "SNYK-DEBIAN10-CURL-358690",
        "SNYK-DEBIAN10-CURL-358560",
        "SNYK-DEBIAN10-CURL-358546",
        "SNYK-DEBIAN10-CURL-358495",
        "SNYK-DEBIAN10-CURL-347426",
        "SNYK-DEBIAN10-CURL-336289",
        "SNYK-DEBIAN10-CURL-336288",
        "SNYK-DEBIAN10-CURL-336286",
        "SNYK-DEBIAN10-CURL-347395"
      ]
    },
    {
      "PkgName": "openssl",
      "FarthestFixedInVersion": "1.1.1d-0+deb10u4",
      "FixesVulns": [
        "SNYK-DEBIAN10-OPENSSL-1049098"
      ]
    },
    {
      "PkgName": "apt",
      "FarthestFixedInVersion": "1.8.2.2",
      "FixesVulns": [
        "SNYK-DEBIAN10-APT-1049974"
      ]
    }
  ]
}
```
