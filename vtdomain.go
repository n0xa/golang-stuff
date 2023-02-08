package main

// VirusTotal domain API client
// Retreive information about domains/hostnames from VirusTotal
// By Noah Axon | IG: @4x0nn | Twitter: @ax0n | GH: n0xa

// ---> You must have a valid VirusTotal API key. <---
// Make sure you set and export the VTAPI environment variable.

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
)

func main() {
	type vtdomain struct {
		DomainSiblings                 []interface{}   `json:"domain_siblings"`
		UndetectedUrls                 [][]interface{} `json:"undetected_urls"`
		UndetectedDownloadedSamples    []interface{}   `json:"undetected_downloaded_samples"`
		Whois                          string          `json:"whois"`
		WhoisTimestamp                 int             `json:"whois_timestamp"`
		DetectedDownloadedSamples      []interface{}   `json:"detected_downloaded_samples"`
		ResponseCode                   int             `json:"response_code"`
		VerboseMsg                     string          `json:"verbose_msg"`
		ForcepointThreatSeekerCategory string          `json:"Forcepoint ThreatSeeker category"`
		Resolutions                    []struct {
			LastResolved string `json:"last_resolved"`
			IPAddress    string `json:"ip_address"`
		} `json:"resolutions"`
		Subdomains   []string      `json:"subdomains"`
		DetectedUrls []interface{} `json:"detected_urls"`
	}

	var VtDomain vtdomain
	baseurl := "https://www.virustotal.com/vtapi"

	exit := 0
	if len(os.Args) < 2 {
		fmt.Println("-> Domain or host name required")
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

	domain := os.Args[1]

	apiurl := fmt.Sprintf("%s/%s?apikey=%s&domain=%s", baseurl, "v2/domain/report", apikey, domain)
	fmt.Println("Querying VirusTotal domain/report API")
	resp, _ := http.Get(apiurl)
	body, err := ioutil.ReadAll(resp.Body)
	defer resp.Body.Close()

	err = json.Unmarshal([]byte(body), &VtDomain)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(" -=-=-=- DNS Resolutions -=-=-=-")
	if len(VtDomain.Resolutions) > 0 {
		fmt.Printf("%*s | %15s | %-25s \n", len(domain), "Name", "IP", "Date")
		for _, resolution := range VtDomain.Resolutions {
			fmt.Printf("%*s | %15s | %-25s \n", len(domain), domain, resolution.IPAddress, resolution.LastResolved)
		}
	} else {
		fmt.Println("Virustotal Returned no Resolutions.")
	}
}
