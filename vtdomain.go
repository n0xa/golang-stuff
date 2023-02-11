package main

// VirusTotal domain API v3 client
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
	"time"
)

type scanresult struct {
	Category   string `json:"category"`
	Result     string `json:"result"`
	Method     string `json:"method"`
	EngineName string `json:"engine_name"`
}

type vtdomain struct {
	Data struct {
		Attributes struct {
			LastDNSRecords []struct {
				Type     string `json:"type"`
				Value    string `json:"value"`
				TTL      int    `json:"ttl"`
				Priority int    `json:"priority,omitempty"`
				Rname    string `json:"rname,omitempty"`
				Retry    int    `json:"retry,omitempty"`
				Minimum  int    `json:"minimum,omitempty"`
				Refresh  int    `json:"refresh,omitempty"`
				Expire   int    `json:"expire,omitempty"`
				Serial   int    `json:"serial,omitempty"`
			} `json:"last_dns_records"`
			Whois           string        `json:"whois"`
			Tags            []interface{} `json:"tags"`
			PopularityRanks struct {
				Statvoo struct {
					Timestamp int `json:"timestamp"`
					Rank      int `json:"rank"`
				} `json:"Statvoo"`
				Alexa struct {
					Timestamp int `json:"timestamp"`
					Rank      int `json:"rank"`
				} `json:"Alexa"`
			} `json:"popularity_ranks"`
			LastAnalysisDate   int `json:"last_analysis_date"`
			LastDNSRecordsDate int `json:"last_dns_records_date"`
			LastAnalysisStats  struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			CreationDate         int                   `json:"creation_date"`
			WhoisDate            int                   `json:"whois_date"`
			Reputation           int                   `json:"reputation"`
			Registrar            string                `json:"registrar"`
			LastAnalysisResults  map[string]scanresult `json:"last_analysis_results"`
			LastUpdateDate       int                   `json:"last_update_date"`
			LastModificationDate int                   `json:"last_modification_date"`
			Categories           struct {
				AlphaMountainAi string `json:"alphaMountain.ai"`
			} `json:"categories"`
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
		} `json:"attributes"`
		Type  string `json:"type"`
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
	} `json:"data"`
}

var VtDomain vtdomain

type vtsubdomain struct {
	Meta struct {
		Count  int    `json:"count"`
		Cursor string `json:"cursor"`
	} `json:"meta"`
	Data []struct {
		Attributes struct {
			LastDNSRecords []struct {
				Type     string `json:"type"`
				Value    string `json:"value"`
				TTL      int    `json:"ttl"`
				Priority int    `json:"priority,omitempty"`
				Rname    string `json:"rname,omitempty"`
				Retry    int    `json:"retry,omitempty"`
				Minimum  int    `json:"minimum,omitempty"`
				Refresh  int    `json:"refresh,omitempty"`
				Expire   int    `json:"expire,omitempty"`
				Serial   int    `json:"serial,omitempty"`
			} `json:"last_dns_records"`
			Whois           string        `json:"whois"`
			Tags            []interface{} `json:"tags"`
			PopularityRanks struct {
			} `json:"popularity_ranks"`
			LastDNSRecordsDate int `json:"last_dns_records_date"`
			LastAnalysisStats  struct {
				Harmless   int `json:"harmless"`
				Malicious  int `json:"malicious"`
				Suspicious int `json:"suspicious"`
				Undetected int `json:"undetected"`
				Timeout    int `json:"timeout"`
			} `json:"last_analysis_stats"`
			CreationDate         int                   `json:"creation_date"`
			Reputation           int                   `json:"reputation"`
			Registrar            string                `json:"registrar"`
			LastAnalysisResults  map[string]scanresult `json:"last_analysis_results"`
			LastUpdateDate       int                   `json:"last_update_date"`
			LastModificationDate int                   `json:"last_modification_date"`
			Categories           struct {
			} `json:"categories"`
			TotalVotes struct {
				Harmless  int `json:"harmless"`
				Malicious int `json:"malicious"`
			} `json:"total_votes"`
		} `json:"attributes"`
		Type  string `json:"type"`
		ID    string `json:"id"`
		Links struct {
			Self string `json:"self"`
		} `json:"links"`
		ContextAttributes struct {
			Timestamp int `json:"timestamp"`
		} `json:"context_attributes"`
	} `json:"data"`
	Links struct {
		Self string `json:"self"`
		Next string `json:"next"`
	} `json:"links"`
}

var VtSubDomain vtsubdomain

func subdomain(apikey, apiurl string) vtsubdomain {
	client := http.Client{}
	req, _ := http.NewRequest("GET", apiurl, nil)
	req.Header = http.Header{"x-apikey": {apikey}}
	resp, _ := client.Do(req)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	err = json.Unmarshal([]byte(body), &VtSubDomain)
	if err != nil {
		log.Fatal(err)
	}
	return VtSubDomain
}

func main() {
	maxpages := 10
	baseurl := "https://www.virustotal.com/api/v3"
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

	apiurl := fmt.Sprintf("%s%s%s%s", baseurl, "/domains/", domain, "?limit=100")
	fmt.Println("Querying VirusTotal v3 domains API")
	client := http.Client{}
	req, _ := http.NewRequest("GET", apiurl, nil)
	req.Header = http.Header{"x-apikey": {apikey}}
	resp, _ := client.Do(req)
	body, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	err = json.Unmarshal([]byte(body), &VtDomain)
	if err != nil {
		log.Fatal(err)
	}

	analysisTime := time.Unix(int64(VtDomain.Data.Attributes.LastAnalysisDate), 0)
	strDate := analysisTime.Format("2006/01/01")

	fmt.Println("\n -=-=-=- Analysis Summary -=-=-=-")
	fmt.Println("Harmless | Suspicious | Malicious | Scan Date  | Hostname ")
	fmt.Printf("%8d | %10d | %9d | %10s | %s \n",
		VtDomain.Data.Attributes.LastAnalysisStats.Harmless+VtDomain.Data.Attributes.LastAnalysisStats.Undetected,
		VtDomain.Data.Attributes.LastAnalysisStats.Suspicious,
		VtDomain.Data.Attributes.LastAnalysisStats.Malicious,
		strDate,
		domain)

	apiurl = fmt.Sprintf("%s%s%s%s", baseurl, "/domains/", domain, "/subdomains?limit=100")
	fmt.Println("Querying VirusTotal v3 domains/subdomain API")

	if len(VtSubDomain.Data) > 0 {
		for _, subdomain := range VtSubDomain.Data {
			analysisTime := time.Unix(int64(subdomain.Attributes.LastUpdateDate), 0)
			strDate := analysisTime.Format("2006/01/01")
			fmt.Printf("%8d | %10d | %9d | %10s | %s \n",
				subdomain.Attributes.LastAnalysisStats.Harmless+subdomain.Attributes.LastAnalysisStats.Undetected,
				subdomain.Attributes.LastAnalysisStats.Suspicious,
				subdomain.Attributes.LastAnalysisStats.Malicious,
				strDate,
				subdomain.ID)
		}
	}

	if len(VtDomain.Data.Attributes.LastDNSRecords) > 0 {
		fmt.Println("\n -=-=-=- Domain DNS Records -=-=-=-")
		fmt.Printf("Type  |   TTL   | %*s | Record\n", len(domain), "Domain")
		for _, dns := range VtDomain.Data.Attributes.LastDNSRecords {
			fmt.Printf("%5s | %7d | %*s | %s\n",
				dns.Type, dns.TTL, len(domain), domain, dns.Value)
		}
	}

	page := 1
	fmt.Println("\nQuerying VirusTotal v3 Domains/Subdomains API")
	fmt.Println(" -=-=-=- Additional Hosts and Subdomains -=-=-=-")
	apiurl = fmt.Sprintf("%s%s%s%s", baseurl, "/domains/", domain, "/subdomains?limit=40")
	for {
		VtSubDomain := subdomain(apikey, apiurl)
		fmt.Printf("Type  |   TTL   | Record\n")
		for _, subdomain := range VtSubDomain.Data {
			for _, dns := range subdomain.Attributes.LastDNSRecords {
				if (dns.Type == "A") || (dns.Type == "CNAME") {
					fmt.Printf("%5s | %7d | %*s -> %s\n",
						dns.Type,
						dns.TTL,
						len(subdomain.ID),
						subdomain.ID,
						dns.Value)
				}
			}
		}
		if len(VtSubDomain.Links.Next) > 1 {
			apiurl = VtSubDomain.Links.Next
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
