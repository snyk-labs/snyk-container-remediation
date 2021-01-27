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

// input types

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

// output types

// Remediation struct
type Remediation struct {
	PkgName                string
	FarthestFixedInVersion string
	FixesVulns             []string `json:"FixesVulns"`
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
	//cliFlag := flag.Bool("cli", false, "enable cli mode")
	flag.Parse()

	if *apiFlag {

		reader := bufio.NewReader(os.Stdin)
		var sb strings.Builder

		for {
			input, err := reader.ReadString('\n')
			if err != nil && err == io.EOF {
				break
			}
			sb.WriteString(input)
		}

		var issues Issues
		upgrades := make(map[string]*Remediation)

		json.Unmarshal([]byte(sb.String()), &issues)

		for i := 0; i < len(issues.Issues); i++ {
			currentPkgName := issues.Issues[i].PkgName

			if issues.Issues[i].IssueData.NearestFixedInVersion == "" {
				break
			}
			if val, ok := upgrades[currentPkgName]; ok {
				// this package already has a map entry
				// check if current issue fixed in is greater than whats already there and add if so
				// append issue ID to the fixesVulns list
				upgrades[currentPkgName].FixesVulns = append(val.FixesVulns, issues.Issues[i].ID)
				currentVersion, _ := version.NewVersion(issues.Issues[i].IssueData.NearestFixedInVersion)
				existingVersion, _ := version.NewVersion(upgrades[currentPkgName].FarthestFixedInVersion)
				if existingVersion.LessThan(currentVersion) {
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
}
