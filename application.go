package main

import (
	"fmt"
	"log"
	"net"
	"recap/lib"
	"strconv"
	"sync"
)

func main() {
	relays, err := lib.GetRelays()

	if err != nil {
		panic(err)
	}

	log.Printf("Successfully retrieved %d relays! Last updated: %s", len(relays.Relays), relays.RelaysPublished)

	tch := make(chan lib.Target, 1)
	och := make(chan lib.Result, 1)

	wgo := sync.WaitGroup{}
	wgt := sync.WaitGroup{}

	for x := 0; x <= 125; x++ {
		wgt.Add(1)
		go func() {
			defer wgt.Done()
			for t := range tch {
				lib.Fingerprint(t, och)
			}
		}()
	}

	wgo.Add(1)
	go func() {
		defer wgo.Done()
		for o := range och {
			if o.Error != nil {
				log.Printf("failed to scan %s:%d: %s", o.Target.Host, o.Target.Port, o.Error)
				continue
			}
			fmt.Printf("JARM,%s:%d,%s\n", o.Target.Host, o.Target.Port, o.Hash)
		}
	}()

	for _, r := range relays.Relays {
		host, p, err := net.SplitHostPort(r.OrAddresses[0])
		if err != nil {
			log.Printf("wtf? %s", err)
		}

		port, _ := strconv.Atoi(p)

		tch <- lib.Target{
			Host: host,
			Port: port,
		}
	}

	// Wait for scans to complete
	close(tch)
	wgt.Wait()

	// Wait for output to finish
	close(och)
	wgo.Wait()
}
