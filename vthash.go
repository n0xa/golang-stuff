package main

// VirusTotal file/report hash API client
// Helps analysts make sense of an unknown file from the CLI

// By Noah Axon | IG: @4x0nn | Twitter: @ax0n | GH: n0xa
// Credits: Lots of help from IG: @totally_not_a_haxxer | GH: ArkAngeL43
// ---> You must have a valid VirusTotal API key. <---
// Make sure you set and export the VTAPI environment variable.

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
)

var words = make(map[string]int)
var regex = regexp.MustCompile(`[^a-zA-Z]+`)
var result string

// some helper functions

func fileHash(filename string) string {
	fh, err := os.Open(filename)
	if err != nil {
		log.Fatal(err)
	}
	defer fh.Close()
	hash := sha256.New()
	if _, err := io.Copy(hash, fh); err != nil {
		log.Fatal(err)
	}
	return (fmt.Sprintf("%x", hash.Sum(nil)))
}

func TopFive(sourcemap map[string]int) []string {
	keys := make([]string, 0, len(sourcemap))
	topfive := make([]string, 0)
	counter := 0
	for key := range sourcemap {
		keys = append(keys, key)
	}
	sort.SliceStable(keys, func(i, j int) bool {
		return sourcemap[keys[i]] > sourcemap[keys[j]]
	})

	for _, k := range keys {
		topfive = append(topfive, k)
		counter += 1
		if counter >= 5 {
			break
		}
	}
	return topfive
}

type vthash struct {
	Data struct {
		ID    string `json:"id"`
		Type  string `json:"type"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		Attributes struct {
			DetectITEasy struct {
				Filetype string `json:"filetype"`
				Values   []struct {
					Info    string `json:"info"`
					Version string `json:"version"`
					Type    string `json:"type"`
					Name    string `json:"name"`
				} `json:"values"`
			} `json:"detectiteasy"`
			VHash            string   `json:"vhash"`
			TimesSubmitted   int      `json:"times_submitted"`
			Names            []string `json:"names"`
			LastAnalysisStats struct {
				Malicious        int `json:"malicious"`
				Suspicious       int `json:"suspicious"`
				Undetected       int `json:"undetected"`
				Harmless         int `json:"harmless"`
				Timeout          int `json:"timeout"`
				ConfirmedTimeout int `json:"confirmed-timeout"`
				Failure          int `json:"failure"`
				TypeUnsupported  int `json:"type-unsupported"`
			} `json:"last_analysis_stats"`
			SHA256 string `json:"sha256"`
			CrowdsourcedYaraResults []struct {
				RulesetID   string `json:"ruleset_id"`
				RuleName    string `json:"rule_name"`
				RulesetName string `json:"ruleset_name"`
				Author      string `json:"author"`
				Source      string `json:"source"`
			} `json:"crowdsourced_yara_results"`
			TLSH     string `json:"tlsh"`
			SSDeep   string `json:"ssdeep"`
			LastSubmissionDate int64 `json:"last_submission_date"`
			TelfHash string `json:"telfhash"`
			TRID     []struct {
				FileType    string  `json:"file_type"`
				Probability float64 `json:"probability"`
			} `json:"trid"`
			Magic         string   `json:"magic"`
			TypeTag       string   `json:"type_tag"`
			LastModificationDate int64 `json:"last_modification_date"`
			FirstSeenITWDate int64 `json:"first_seen_itw_date"`
			Size     int    `json:"size"`
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
			ELFInfo struct {
				Header struct {
					HdrVersion      string `json:"hdr_version"`
					Type            string `json:"type"`
					NumProgHeaders  int    `json:"num_prog_headers"`
					ObjVersion      string `json:"obj_version"`
					Machine         string `json:"machine"`
					NumSectionHeaders int  `json:"num_section_headers"`
					OSABI           string `json:"os_abi"`
					ABIVersion      int    `json:"abi_version"`
					Entrypoint      int    `json:"entrypoint"`
					Data            string `json:"data"`
					Class           string `json:"class"`
				} `json:"header"`
				ExportList []struct {
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"export_list"`
				ImportList []struct {
					Name string `json:"name"`
					Type string `json:"type"`
				} `json:"import_list"`
				SectionList []struct {
					Name            string `json:"name"`
					SectionType     string `json:"section_type"`
					VirtualAddress  int    `json:"virtual_address"`
					PhysicalOffset  int    `json:"physical_offset"`
					Size            int    `json:"size"`
					Flags           string `json:"flags"`
				} `json:"section_list"`
				SegmentList []struct {
					SegmentType string   `json:"segment_type"`
					Resources   []string `json:"resources"`
				} `json:"segment_list"`
			} `json:"elf_info"`
			Reputation       int    `json:"reputation"`
			MD5              string `json:"md5"`
			UniqueSources    int    `json:"unique_sources"`
			FirstSubmissionDate int64 `json:"first_submission_date"`
			SandboxVerdicts  struct {
				ZenboxLinux struct {
					Category              string   `json:"category"`
					Confidence            int      `json:"confidence"`
					SandboxName           string   `json:"sandbox_name"`
					MalwareClassification []string `json:"malware_classification"`
					MalwareNames          []string `json:"malware_names"`
				} `json:"Zenbox Linux"`
			} `json:"sandbox_verdicts"`
			SHA1      string   `json:"sha1"`
			TypeTags  []string `json:"type_tags"`
			LastAnalysisResults map[string]struct {
				Method        string `json:"method"`
				EngineName    string `json:"engine_name"`
				EngineVersion string `json:"engine_version"`
				EngineUpdate  string `json:"engine_update"`
				Category      string `json:"category"`
				Result        string `json:"result,omitempty"`
			} `json:"last_analysis_results"`
			MeaningfulName     string   `json:"meaningful_name"`
			Tags               []string `json:"tags"`
			LastAnalysisDate   int64    `json:"last_analysis_date"`
			TypeDescription    string   `json:"type_description"`
		} `json:"attributes"`
	} `json:"data"`
}

func main() {
	baseurl := "https://www.virustotal.com/api/v3"
	exit := 0
	if len(os.Args) < 2 {
		fmt.Println("-> File Name, SHA-512, SHA-256, MD5 Hash or VT Scan-Id expected as first argument.")
		exit += 1
	}
	apikey := os.Getenv("VTAPI")
	if len(apikey) < 64 {
		fmt.Println("-> Export the VTAPI environment variable with your VirusTotal API key.")
		exit += 2
	}
	if exit > 0 {
		// this way we can get all of the errors out before exiting
		os.Exit(exit)
	}

	filehash := os.Args[1]

	// Let's see if the argument is a file. If so, hash that.
	_, err := os.Stat(os.Args[1])
	if err != nil {
	} else {
		filehash = fileHash(os.Args[1])
		fmt.Println("File", os.Args[1], "has hash", filehash)
	}

	fmt.Println("Querying VirusTotal file/report API")

	apiurl := fmt.Sprintf("%s%s%s", baseurl, "/files/", filehash)
	client := http.Client{}
	req, _ := http.NewRequest("GET", apiurl, nil)
	req.Header = http.Header{"x-apikey": {apikey}}
	resp, _ := client.Do(req)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	var VtHash vthash
	err = json.Unmarshal(body, &VtHash)
	if err != nil {
		log.Fatal(err)
	}
	resultcount := 0
	falsecount := 0
	fmt.Printf("%23s | %s \n", "Scan Engine", "Detection Result")
	fmt.Printf("%23s | %s \n", "-----------------------", "------------------")
	for engine, scan := range VtHash.Data.Attributes.LastAnalysisResults {
		if scan.Result != "" {
			resultcount += 1
			resultwords := regex.ReplaceAllString(scan.Result, " ")
			for _, word := range strings.Split(resultwords, " ") {
				if len(word) > 3 {
					words[strings.Title(strings.ToLower(word))] += 1
				}
			}
			fmt.Printf("%23s | %s \n", engine, scan.Result)
		} else {
			falsecount += 1
		}
	}
	fmt.Println(resultcount, "detections,", falsecount, "scanners with no results")
	fmt.Println("Most common words:", TopFive(words))
}
