package main

import (
	"bufio"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/hashicorp/go-version"
)

// API JSON input types

// Issues struct
type Issues struct {
	Issues []Issue `json:"issues"`
}

// Issue struct
type Issue struct {
	ID        string    `json:"id"`
	PkgName   string    `json:"pkgName"`
	IssueData IssueData `json:"issueData"`
	FixInfo   FixInfo   `json:"fixInfo"`
}

// IssueData struct
type IssueData struct {
	NearestFixedInVersion string `json:"nearestFixedInVersion"`
}

// FixInfo struct
type FixInfo struct {
	IsUpgradable bool `json:"isUpgradable"`
}

// CLI JSON input types

// Vulnerabilities struct
type Vulnerabilities struct {
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability struct
type Vulnerability struct {
	ID                    string `json:"id"`
	PackageName           string `json:"packageName"`
	NearestFixedInVersion string `json:"nearestFixedInVersion"`
}

// output types

// Remediation struct
type Remediation struct {
	PkgName                string
	FarthestFixedInVersion string
	FixesVulns             []string `json:"FixesVulns"`
}

func getRemediationFromAPIJSON(APIIssuesJSON string) map[string]*Remediation {
	var issues Issues
	upgrades := make(map[string]*Remediation)

	json.Unmarshal([]byte(APIIssuesJSON), &issues)

	for i := 0; i < len(issues.Issues); i++ {
		currentPkgName := issues.Issues[i].PkgName

		if issues.Issues[i].IssueData.NearestFixedInVersion == "" {
			continue
		}
		if val, ok := upgrades[currentPkgName]; ok {
			// this package already has a map entry
			// append issue ID to the fixesVulns list
			if findInSlice(val.FixesVulns, issues.Issues[i].ID) == false {
				upgrades[currentPkgName].FixesVulns = append(val.FixesVulns, issues.Issues[i].ID)
			}

			currentVersion, _ := version.NewVersion(issues.Issues[i].IssueData.NearestFixedInVersion)
			existingVersion, _ := version.NewVersion(upgrades[currentPkgName].FarthestFixedInVersion)

			// check if current issue fixed in is greater than whats already there and add if so
			if existingVersion != nil && existingVersion.LessThan(currentVersion) {
				upgrades[currentPkgName].FarthestFixedInVersion = currentVersion.String()
			}

		} else {
			// this package has not been seen yet, add 1st remediation entry
			var remediation Remediation
			remediation.PkgName = currentPkgName
			remediation.FarthestFixedInVersion = issues.Issues[i].IssueData.NearestFixedInVersion
			remediation.FixesVulns = append(remediation.FixesVulns, issues.Issues[i].ID)
			upgrades[issues.Issues[i].PkgName] = &remediation
		}
	}

	return upgrades
}

func getRemediationFromCLIJSON(CLIIssuesJSON string) map[string]*Remediation {
	var vulnerabilities Vulnerabilities
	upgrades := make(map[string]*Remediation)

	json.Unmarshal([]byte(CLIIssuesJSON), &vulnerabilities)

	for i := 0; i < len(vulnerabilities.Vulnerabilities); i++ {
		currentPkgName := vulnerabilities.Vulnerabilities[i].PackageName

		if vulnerabilities.Vulnerabilities[i].NearestFixedInVersion == "" {
			continue
		}
		if val, ok := upgrades[currentPkgName]; ok {
			// this package already has a map entry
			// append issue ID to the fixesVulns list
			if findInSlice(val.FixesVulns, vulnerabilities.Vulnerabilities[i].ID) == false {
				upgrades[currentPkgName].FixesVulns = append(val.FixesVulns, vulnerabilities.Vulnerabilities[i].ID)
			}
			currentVersion, _ := version.NewVersion(vulnerabilities.Vulnerabilities[i].NearestFixedInVersion)
			existingVersion, _ := version.NewVersion(upgrades[currentPkgName].FarthestFixedInVersion)

			// check if current issue fixed in is greater than whats already there and add if so
			if existingVersion != nil && existingVersion.LessThan(currentVersion) {
				upgrades[currentPkgName].FarthestFixedInVersion = currentVersion.String()
			}
		} else {
			// this package has not been seen yet, add 1st remediation entry
			var remediation Remediation
			remediation.PkgName = currentPkgName
			remediation.FarthestFixedInVersion = vulnerabilities.Vulnerabilities[i].NearestFixedInVersion
			remediation.FixesVulns = append(remediation.FixesVulns, vulnerabilities.Vulnerabilities[i].ID)
			upgrades[vulnerabilities.Vulnerabilities[i].PackageName] = &remediation
		}
	}
	return upgrades
}

func printUpgradesJSON(upgrades map[string]*Remediation) {
	fmt.Println("{\n  \"upgrades\": [")
	i := 1
	for j := range upgrades {
		outputJSON, _ := json.MarshalIndent(upgrades[j], "", "  ")
		fmt.Print("    ")
		for k := range outputJSON {
			fmt.Printf("%s", string(outputJSON[k]))
			if string(outputJSON[k]) == "\n" {
				fmt.Print("    ")
			}
		}
		if i < len(upgrades) {
			fmt.Println(",")
		}
		i++
	}
	fmt.Println("\n  ]\n}")
}

func findInSlice(slice []string, val string) bool {
	for item := range slice {
		if slice[item] == val {
			return true
		}
	}
	return false
}

func main() {
	info, err := os.Stdin.Stat()
	if err != nil {
		panic(err)
	}

	if info.Mode()&os.ModeCharDevice != 0 || info.Size() <= 0 {
		fmt.Println("The command is intended to work with pipes.")
		return
	}

	apiFlag := flag.Bool("api", false, "enable api mode")
	cliFlag := flag.Bool("cli", false, "enable cli mode")
	flag.Parse()

	reader := bufio.NewReader(os.Stdin)
	var sb strings.Builder

	for {
		input, err := reader.ReadString('\n')
		if err != nil && err == io.EOF {
			break
		}
		sb.WriteString(input)
	}

	if *apiFlag {
		upgrades := getRemediationFromAPIJSON(sb.String())
		printUpgradesJSON(upgrades)
	} else if *cliFlag {
		//fmt.Print(sb.String())
		upgrades := getRemediationFromCLIJSON(sb.String())
		printUpgradesJSON(upgrades)
	} else {
		fmt.Println("--api or --cli is required")
	}
}
