package main

// VirusTotal file/report hash API client
// Helps analysts make sense of an unknown file from the CLI

// By Noah Axon | IG: @4x0nn | Twitter: @ax0n | GH: n0xa
// Credits: Lots of help from IG: @totally_not_a_haxxer | GH: ArkAngeL43
// ---> You must have a valid VirusTotal API key. <--- 
// Make sure you set and export the VTAPI environment variable.

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sort"
	"crypto/sha256"
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
	return(fmt.Sprintf("%x", hash.Sum(nil)))
}

func GetKey(val map[string]interface{}) (arr []string) {
	for i := range val {
		arr = append(arr, fmt.Sprint(i))
	}
	return arr
}

// todo: handle file-not-known-by-VT case, upload file by default?
// example json when resource not known:
//{
//  "response_code": 0,
//  "resource": "0123456789abcdef9301829198",
//  "verbose_msg": "The requested resource is not among the finished, queued or pending scans"
//}

func TopFive(sourcemap map[string]int) []string {
	keys := make([]string, 0, len(sourcemap))
    topfive := make([]string, 0)
	counter := 0
    for key := range sourcemap {
        keys = append(keys, key)
    }
    sort.SliceStable(keys, func(i, j int) bool{
        return sourcemap[keys[i]] > sourcemap[keys[j]]
    })

    for _, k := range keys{
		topfive = append(topfive, k)
		counter += 1
		if counter >= 5 {
			break
		}
    }
	return topfive
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

	// simple MSI instead of trying to wrangle this JSON with a struct
	var DataMap map[string]interface{}
	err = json.Unmarshal(body, &DataMap)
	if err != nil {
		log.Fatal(err)
	}

    // Recursive digging into scans returned by VirusTotal
    resultcount := 0
	fmt.Println("Detections:")
	for _, value := range DataMap { 
		if fmt.Sprintf("%T", value) == "map[string]interface {}" {
			newmap := value.(map[string]interface{})
			mapkeys := GetKey(newmap) 
			for i := 0; i < len(mapkeys); i++ {
				secval := newmap[mapkeys[i]]
				if secval != nil {
					secondary := secval.(map[string]interface{})
					if secondary["result"] != nil {
						if result, ok := secondary["result"].(string); ok {
							resultcount += 1
							resultwords := regex.ReplaceAllString(result," ")
							for _, word := range(strings.Split(resultwords, " ")){
								if len(word) > 3 {
									words[strings.Title(strings.ToLower(word))] += 1
								}
							}
							fmt.Println("-->",result)
						}
					}
				}
			}
		}
	}
	fmt.Println(resultcount, "detections")
	fmt.Println("Most common words:", TopFive(words))
}
