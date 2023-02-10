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
	"net/url"
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

type scanresult struct {
	Detected bool   `json:"detected"`
	Version  string `json:"version"`
	Result   string `json:"result"`
	Update   string `json:"update"`
}

type vthash struct {
	Scans        map[string]scanresult `json:"scans"`
	ScanID       string                `json:"scan_id"`
	Sha1         string                `json:"sha1"`
	Resource     string                `json:"resource"`
	ResponseCode int                   `json:"response_code"`
	ScanDate     string                `json:"scan_date"`
	Permalink    string                `json:"permalink"`
	VerboseMsg   string                `json:"verbose_msg"`
	Total        int                   `json:"total"`
	Positives    int                   `json:"positives"`
	Sha256       string                `json:"sha256"`
	Md5          string                `json:"md5"`
}

func main() {
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

	data := url.Values{
		"apikey":   {apikey},
		"resource": {filehash},
	}
	fmt.Println("Querying VirusTotal file/report API")
	resp, _ := http.PostForm("https://www.virustotal.com/vtapi/v2/file/report", data)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	var VtHash vthash
	err = json.Unmarshal(body, &VtHash)
	if err != nil {
		log.Fatal(err)
	}

	resultcount := 0
	falsecount := 0
	if VtHash.ResponseCode == 0 {
		fmt.Println(VtHash.VerboseMsg)
		os.Exit(0)
	}
	fmt.Printf("%23s | %s \n", "Scan Engine", "Detection Result")
	fmt.Printf("%23s | %s \n", "-----------------------", "------------------")
	for engine, scan := range VtHash.Scans {
		if scan.Detected {
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
