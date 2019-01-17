package main

import (
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"log"
	"os"
	"sync"
	"time"
)

func main() {
	app := argsParserSetup()
	app.Action = argsHandler
	err := app.Run(os.Args)
	if err != nil {
		log.Fatalf("Parse args error: ", err.Error())
	}

	log.Printf("V: %s, R: %s, D: %s, Forever: %t\n", vaultUrl, vaultRole, dbRole, runForever)

	loginVault()
	log.Printf("Loop count: %d, Concurrency: %d\n", loopCount, concurrency)

	if loopCount > 0 {
		for {
			makeLimitedRequests()

			if !runForever {
				log.Println("Not run forever")
				break
			}
			loginVault()
		}
		log.Println("Program exit.")
		os.Exit(0)
	} else {
		concurrency := make(chan int, concurrency)
		for {
			if count := remaining.getCount(); count < 5000 {
				log.Println(count, " request left. Add 5000 request to go routine.")
				remaining.addCount(5000)
				for i := 0; i < 5000; i++ {
					go getDbCred(nil, concurrency)
				}
			}

			if tokenExpire.Sub(time.Now()).Seconds() < 600 {
				loginVault()
				log.Println("Vault token renewed.")
			}

			time.Sleep(1 * time.Second)
		}

	}
}

func makeLimitedRequests() {
	concurrency := make(chan int, concurrency)
	wg := sync.WaitGroup{}
	wg.Add(loopCount)
	for i := 0; i < loopCount; i++ {
		go getDbCred(&wg, concurrency)
	}
	wg.Wait()
	close(concurrency)
	log.Printf("Request is done. Sleep %d seconds.\n", sleepSecond)
	time.Sleep(time.Duration(sleepSecond) * time.Second)
}

type lockCounter struct {
	sync.Mutex
	count int
}

func (a *lockCounter) getCount() int {
	a.Lock()
	defer a.Unlock()

	return a.count
}

func (a *lockCounter) addCount(n int) {
	a.Lock()
	defer a.Unlock()

	a.count = a.count + n
}

var remaining lockCounter
var tokenExpire time.Time

var vaultUrl string
var vaultRole string
var dbRole string
var loopCount int
var concurrency int
var sleepSecond int
var runForever bool
var tlsConf = &vault.TLSConfig{Insecure: true}

var vaultClient = &vault.Client{}

func argsParserSetup() *cli.App {
	app := cli.NewApp()
	app.Name = "Vault Test"
	app.Usage = "make an explosive entrance"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "vault,v",
			Usage:       "vault url.",
			Destination: &vaultUrl,
		},
		cli.StringFlag{
			Name:        "role,r",
			Usage:       "Login to vault with role provided.",
			Destination: &vaultRole,
		},
		cli.StringFlag{
			Name:        "db",
			Usage:       "Obtain which db role.",
			Destination: &dbRole,
		},
		cli.IntFlag{
			Name:        "count",
			Usage:       "How many credential is go to obtain",
			Value:       1,
			Destination: &loopCount,
		},
		cli.IntFlag{
			Name:        "concurrency",
			Usage:       "How many concurrency",
			Value:       10,
			Destination: &concurrency,
		},
		cli.IntFlag{
			Name:        "sleep",
			Usage:       "How many second it sleepSecond before exit.",
			Value:       0,
			Destination: &sleepSecond,
		},
		cli.BoolFlag{
			Name:        "forever",
			Usage:       "Let program run forever",
			Destination: &runForever,
		},
	}
	app.HideVersion = true
	app.HideHelp = true

	return app
}

func argsHandler(c *cli.Context) error {
	needHelp := c.Bool("help")
	if needHelp {
		cli.ShowAppHelpAndExit(c, 1)
	}
	return nil
}

func loginVault() {
	vaultConfig := &vault.Config{Address: vaultUrl}
	configErr := vaultConfig.ConfigureTLS(tlsConf)
	if configErr != nil {
		log.Fatalf("Config vault TLS error: %s\n", configErr)
	}
	client, err := vault.NewClient(vaultConfig)
	if err != nil {
		log.Fatalf("Create vault client error: %s\n", err)
	}

	logical := client.Logical()

	jwt, err := ioutil.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/token")
	if err != nil {
		log.Fatalf("Read SA JWT error: %s\n", err)
	}

	loginPayload := map[string]interface{}{"jwt": string(jwt), "role": vaultRole}
	secret, err := logical.Write("auth/kubernetes/login", loginPayload)
	if err != nil {
		log.Fatalf("Login error: %s\n", err)
	}
	client.SetToken(secret.Auth.ClientToken)
	tokenExpire = time.Now().Add(time.Duration(time.Duration(secret.Auth.LeaseDuration) * time.Second))

	vaultClient = client
}

func getDbCred(wg *sync.WaitGroup, concurrency chan int) {
	concurrency <- 0

	logical := vaultClient.Logical()

	_, err := logical.Read(fmt.Sprintf("/database/creds/%s", dbRole))
	if err != nil {
		log.Fatalf("Read DB credential error: %s\n", err)

	}
	<-concurrency

	if wg != nil {
		wg.Done()
	} else {
		remaining.addCount(-1)
	}
}
