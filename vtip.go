package main

// VirusTotal IP Addresses API v3 client
// Retreive information about IP Reputation and hostnames from VirusTotal
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
	"time"
)

type scanresult struct {
	Category   string `json:"category"`
	Result     string `json:"result"`
	Method     string `json:"method"`
	EngineName string `json:"engine_name"`
}

type vtip struct {
	Data struct {
		Attributes struct {
			RegionalInternetRegistry string        `json:"regional_internet_registry"`
			Jarm                     string        `json:"jarm"`
			Network                  string        `json:"network"`
			Tags                     []interface{} `json:"tags"`
			Country                  string        `json:"country"`
			LastAnalysisDate         int           `json:"last_analysis_date"`
			AsOwner                  string        `json:"as_owner"`
			LastAnalysisStats        struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			Asn                  int                   `json:"asn"`
			WhoisDate            int                   `json:"whois_date"`
			LastAnalysisResults  map[string]scanresult `json:"last_analysis_results"`
			Reputation           int                   `json:"reputation"`
			LastModificationDate int                   `json:"last_modification_date"`
			TotalVotes           struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
			Continent string `json:"continent"`
			Whois     string `json:"whois"`
		} `json:"attributes"`
		Type  string `json:"type"`
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	} `json:"data"`
}

var VtIP vtip

type vtipresolutions struct {
	Meta struct {
		Count int `json:"count"`
	} `json:"meta"`
	Data []struct {
		Attributes struct {
			Date                       int    `json:"date"`
			HostName                   string `json:"host_name"`
			Resolver                   string `json:"resolver"`
			IPAddressLastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"ip_address_last_analysis_stats"`
			IPAddress                 string `json:"ip_address"`
			HostNameLastAnalysisStats struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"host_name_last_analysis_stats"`
		} `json:"attributes"`
		Type  string `json:"type"`
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	} `json:"data"`
	Links struct {
		Self string `json:"self"`
		Next string `json:"next"`
	} `json:"links"`
}

var VtIPResolutions vtipresolutions

func resolve(apikey, apiurl string) vtipresolutions {
	fmt.Println("Querying VirusTotal v3 IP Address/Resolutions API")
	client := http.Client{}
	req, _ := http.NewRequest("GET", apiurl, nil)
	req.Header = http.Header{"x-apikey": {apikey}}
	resp, _ := client.Do(req)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	err = json.Unmarshal([]byte(body), &VtIPResolutions)
	if err != nil {
		log.Fatal(err)
	}
	return VtIPResolutions
}

func main() {
	maxpages := 10
	baseurl := "https://www.virustotal.com/api/v3"
	exit := 0
	if len(os.Args) < 2 {
		fmt.Println("-> IP Address required")
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

	ip := os.Args[1]

	apiurl := fmt.Sprintf("%s%s%s", baseurl, "/ip_addresses/", ip)
	client := http.Client{}
	req, _ := http.NewRequest("GET", apiurl, nil)
	req.Header = http.Header{"x-apikey": {apikey}}
	resp, _ := client.Do(req)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	err = json.Unmarshal([]byte(body), &VtIP)
	if err != nil {
		log.Fatal(err)
	}

	strDate := time.Unix(int64(VtIP.Data.Attributes.LastAnalysisDate), 0).Format("2006/01/01")

	fmt.Println("\n -=-=-=- Analysis Summary -=-=-=-")
	fmt.Println("Harmless | Suspicious | Malicious | Scan Date  | ip")
	fmt.Printf("%8d | %10d | %9d | %10s | %s \n",
		VtIP.Data.Attributes.LastAnalysisStats.Harmless+VtIP.Data.Attributes.LastAnalysisStats.Undetected,
		VtIP.Data.Attributes.LastAnalysisStats.Suspicious,
		VtIP.Data.Attributes.LastAnalysisStats.Malicious,
		strDate,
		ip)

	page := 1
	fmt.Println("Querying VirusTotal v3 IP Addresses API")
	fmt.Println("\n -=-=-=- DNS Hostnames -=-=-=-")
	apiurl = fmt.Sprintf("%s%s%s%s", baseurl, "/ip_addresses/", ip, "/resolutions?limit=40")
	for {
		VtIPResolutions := resolve(apikey, apiurl)
		fmt.Println("   Date    | Mal | Sus |    IP Address    | Hostname")
		for _, dns := range VtIPResolutions.Data {
			strDate := time.Unix(int64(dns.Attributes.Date), 0).Format("2006/01/01")
			fmt.Printf("%10s | %3d | %3d | %16s | %s\n",
				strDate,
				dns.Attributes.HostNameLastAnalysisStats.Malicious,
				dns.Attributes.HostNameLastAnalysisStats.Suspicious,
				ip,
				dns.Attributes.HostName)
		}
		if len(VtIPResolutions.Links.Next) > 1 {
			apiurl = VtIPResolutions.Links.Next
			page += 1
			if page > maxpages {
				fmt.Println(" Page limit reached, terminating.")
				break
			}
			fmt.Println(" ... Fetching page ", page, "of results ...")
		} else {
			break
		}
	}
}
