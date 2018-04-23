package main

import (
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"reflect"
	"strings"
	"time"

	"encoding/csv"
	"gopkg.in/routeros.v2"
)

var (
	address       = flag.String("address", "192.168.88.1:8728", "RouterOS address and port")
	username      = flag.String("username", "admin", "User name")
	password      = flag.String("password", "admin", "Password")
	out_interface = flag.String("interface", "vpn", "VPN interface")
	verbose       = flag.Bool("verbose", false, "Verbose mode")
	rules         = flag.Int("rules", 1, "Rules for: 0 - all, 1 - networks, 2 - IP")
	apply_rules   = flag.Bool("apply", false, "Apply rules to router: true - yes, false - no")
	timeout       = flag.Duration("timeout", 4*time.Second, "Connection timeout")
)

type RType int

const (
	Nat    RType = 0
	Mangle RType = 1
	Routes RType = 2
)

func check(e error) {
	if e != nil {
		log.Fatal(e)
	}
}

func main() {
	flag.Parse()
	if *out_interface == "" {
		flag.Usage()
		return
	}
	c, err := routeros.DialTimeout(*address, *username, *password, *timeout)
	check(err)
	defer c.Close()
	c.Queue = 100
	ips := readIps()
	log.Printf("Count select IP & Networks: %d", len(ips))

	nat := getIps(c, Nat)
	if *verbose {
		log.Printf("Nat count ips: %d", len(nat))
	}
	mangle := getIps(c, Mangle)
	if *verbose {
		log.Printf("Mangle count ips: %d", len(mangle))
	}
	routes := getIps(c, Routes)
	if *verbose {
		log.Printf("Routes count ips: %d", len(routes))
	}
	for _, ip := range ips {
		in_nat, _ := in_array(ip, nat)
		in_mangle, _ := in_array(ip, mangle)
		in_routes, _ := in_array(ip, routes)
		if *verbose {
			log.Printf("ip: %s, in-nat: %t, in-mangle: %t, in-routes: %t", ip, in_nat, in_mangle, in_routes)
		}
		if *apply_rules {
			log.Println("trying to apply rules")
			if in_nat == false {
				log.Printf("applying nat rules for ip: %s", ip)
				res := addIp(c, ip, Nat)
				if *verbose {
					log.Println(res)
				}
			}
			if in_mangle == false {
				log.Printf("applying mangle rules for ip: %s", ip)
				res := addIp(c, ip, Mangle)
				if *verbose {
					log.Println(res)
				}
			}
			if in_routes == false {
				log.Printf("applying route rules for ip: %s", ip)
				res := addIp(c, ip, Routes)
				if *verbose {
					log.Println(res)
				}
			}
		}
	}

	c.Close()

}

func addIp(c *routeros.Client, ip string, t RType) (l string) {
	var request []string
	if t == Nat {
		request = append(
			request,
			"/ip/firewall/nat/add",
			"=chain=srcnat",
			"=action=masquerade",
			"=log=no",
			"=log-prefix=\"\"",
			fmt.Sprintf("=out-interface=%s", *out_interface),
			fmt.Sprintf("=dst-address=%s", ip),
		)
	} else if t == Mangle {
		request = append(
			request,
			"/ip/firewall/mangle/add",
			"=chain=prerouting",
			"=action=mark-routing",
			"=new-routing-mark=L2TP",
			"=passthrough=yes",
			"=log=no",
			"=log-prefix=\"\"",
			fmt.Sprintf("=dst-address=%s", ip),
		)
	} else if t == Routes {
		request = append(
			request,
			"/ip/route/add",
			"=distance=1",
			"=scope=30",
			"=target-scope=10",
			"=routing-mark=L2TP",
			fmt.Sprintf("=gateway=%s", *out_interface),
			fmt.Sprintf("=dst-address=%s", ip),
		)
	}
	if *verbose {
		log.Printf("addIp: %s", request)
	}
	l = run(c, request)
	return l
}

func getIps(c *routeros.Client, t RType) (l []string) {
	var request string
	if t == Nat {
		request = "/ip/firewall/nat/print"
	} else if t == Mangle {
		request = "/ip/firewall/mangle/print"
	} else if t == Routes {
		request = "/ip/route/print"
	}
	if *verbose {
		log.Printf("getIp: %s", request)
	}
	result := listen(c, request)

	err := result.Err()
	if err != nil {
		log.Fatal(err)
	}

	for sen := range result.Chan() {
		chain := sen.Map["chain"]
		action := sen.Map["action"]
		dst_address := sen.Map["dst-address"]
		if dst_address != "" {
			if t == Nat || t == Mangle {
				if (chain == "srcnat" && action == "masquerade") || (chain == "prerouting" && action == "mark-routing") {
					l = append(l, dst_address)
				}
			} else if t == Routes {
				l = append(l, dst_address)
			}
		}
	}
	return l
}

func run(c *routeros.Client, command []string) string {
	l, err := c.RunArgs(command)
	check(err)
	return l.String()
}

func listen(c *routeros.Client, command string) (l *routeros.ListenReply) {
	l, err := c.Listen(command)
	check(err)

	go func() {
		time.Sleep(*timeout)
		log.Print("Cancelling the RouterOS command...")
		_, err := l.Cancel()
		if err != nil {
			log.Fatal(err)
		}
	}()

	return l
}

func readIps() (ips []string) {
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
					if (*rules == 1 || *rules == 0) && mask != nil {
						ips = append(ips, ip)
					}
					if (*rules == 2 || *rules == 0) && ipp != nil {
						ips = append(ips, ip)
					}
				}
			}
		}
	}

	return ips
}

func in_array(val interface{}, array interface{}) (exists bool, index int) {
	exists = false
	index = -1

	switch reflect.TypeOf(array).Kind() {
	case reflect.Slice:
		s := reflect.ValueOf(array)

		for i := 0; i < s.Len(); i++ {
			if reflect.DeepEqual(val, s.Index(i).Interface()) == true {
				index = i
				exists = true
				return
			}
		}
	}

	return
}
