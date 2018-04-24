package main

import (
	"fmt"
	"io"
	"io/ioutil"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"encoding/csv"
)

type IPType int

const (
	FirstIP IPType = 0
	LastIP  IPType = 1
)

func readIps() (ips []string) {
	ip_list := make(map[string][]int)
	resp, err := http.Get("https://raw.githubusercontent.com/zapret-info/z-i/master/dump.csv")
	check(err)
	defer resp.Body.Close()
	body, err := ioutil.ReadAll(resp.Body)
	check(err)

	in := string(body)

	r := csv.NewReader(strings.NewReader(in))
	r.LazyQuotes = true
	r.Comma = ','
	r.Comment = '#'

	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}
		if record != nil && len(record) > 0 {
			rows := strings.Split(record[0], ";")
			if len(rows) > 1 {
				ipl := strings.Split(rows[0], "|")
				for _, ip := range ipl {
					_, mask, _ := net.ParseCIDR(ip)
					ipp := net.ParseIP(ip)
					if mask != nil && (*rules == 0 || *rules == 1) {
						ips = append(ips, ip)
					}
					if ipp != nil {
						ip_arr := strings.Split(ip, ".")
						host := fmt.Sprintf("%s.%s.%s", ip_arr[0], ip_arr[1], ip_arr[2])
						last, _ := strconv.Atoi(ip_arr[3])
						ip_list[host] = append(ip_list[host], last)
						sort.Ints(ip_list[host])
					}
				}
			}
		}
	}
	for sub := range ip_list {
		count := len(ip_list[sub])
		first := getIP(ip_list[sub][0], FirstIP)
		last := getIP(ip_list[sub][count-1], LastIP)
		count_ips := (last - first)
		if count >= 5 && count_ips >= 5 {
			if *rules == 0 || *rules == 1 {
				ips = append(ips, fmt.Sprintf("%s.%d/%d", sub, first, ip_size(count_ips)))
			}
		} else {
			if *rules == 0 || *rules == 2 {
				for _, ipp := range ip_list[sub] {
					ips = append(ips, fmt.Sprintf("%s.%d", sub, ipp))
				}
			}
		}
	}
	return uniqueIps(ips)
}

func uniqueIps(intSlice []string) []string {
	keys := make(map[string]bool)
	list := []string{}
	for _, entry := range intSlice {
		if _, value := keys[entry]; !value {
			keys[entry] = true
			list = append(list, entry)
		}
	}
	return list
}

func getIP(c int, t IPType) (first int) {
	if c >= 0 && c <= 15 {
		if t == FirstIP {
			return 0
		}
		return 15
	} else if c >= 16 && c <= 31 {
		if t == FirstIP {
			return 16
		}
		return 31
	} else if c >= 32 && c <= 47 {
		if t == FirstIP {
			return 32
		}
		return 47
	} else if c >= 48 && c <= 63 {
		if t == FirstIP {
			return 48
		}
		return 63
	} else if c >= 64 && c <= 79 {
		if t == FirstIP {
			return 64
		}
		return 79
	} else if c >= 80 && c <= 95 {
		if t == FirstIP {
			return 80
		}
		return 95
	} else if c >= 96 && c <= 111 {
		if t == FirstIP {
			return 96
		}
		return 111
	} else if c >= 112 && c <= 127 {
		if t == FirstIP {
			return 112
		}
		return 127
	} else if c >= 128 && c <= 143 {
		if t == FirstIP {
			return 128
		}
		return 143
	} else if c >= 144 && c <= 159 {
		if t == FirstIP {
			return 144
		}
		return 159
	} else if c >= 160 && c <= 175 {
		if t == FirstIP {
			return 160
		}
		return 175
	} else if c >= 176 && c <= 191 {
		if t == FirstIP {
			return 176
		}
		return 191
	} else if c >= 192 && c <= 207 {
		if t == FirstIP {
			return 192
		}
		return 207
	} else if c >= 208 && c <= 223 {
		if t == FirstIP {
			return 208
		}
		return 223
	} else if c >= 224 && c <= 239 {
		if t == FirstIP {
			return 224
		}
		return 239
	} else {
		if t == FirstIP {
			return 240
		}
		return 255
	}
}

func ip_size(c int) int {
	if c < 4 {
		return 30
	} else if c >= 4 && c < 8 {
		return 29
	} else if c >= 8 && c < 16 {
		return 28
	} else if c >= 16 && c < 32 {
		return 27
	} else if c >= 32 && c < 64 {
		return 26
	} else if c >= 64 && c < 128 {
		return 25
	}
	return 24
}
