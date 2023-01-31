package main

// VirusTotal file/report hash API client
// Helps analysts make sense of an unknown file from the CLI

// By Noah Axon | IG: @4x0nn | Twitter: @ax0n | GH: n0xa
// Credits: Lots of help from IG: @totally_not_a_haxxer | GH: ArkAngeL43
// ---> You must have a valid VirusTotal API key. <--- 
// Make sure you set and export the VTAPI environment variable.
//
import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
)


// some helper functions 

func GetKey(val map[string]interface{}) (arr []string) {
	for i := range val {
		arr = append(arr, fmt.Sprint(i))
	}
	return arr
}

func main() {
	exit := 0
	if len(os.Args) < 2 {
		fmt.Println("-> SHA-512, SHA-256, MD5 Hash or VT Scan-Id expected as first argument.")
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
	data := url.Values{
		"apikey":   {apikey},
		"resource": {filehash},
	}

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
	for _, value := range DataMap { 
		if fmt.Sprintf("%T", value) == "map[string]interface {}" {
			newmap := value.(map[string]interface{})
			mapkeys := GetKey(newmap) 
			for i := 0; i < len(mapkeys); i++ {
				secval := newmap[mapkeys[i]]
				if secval != nil {
					secondary := secval.(map[string]interface{})
					if secondary["result"] != nil {
						fmt.Println(secondary["result"])
					}
				}
			}
		}
	}
}
