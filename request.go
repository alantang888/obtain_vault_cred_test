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

	log.Printf("V: %s, R: %s, D: %s\n", vaultUrl, vaultRole, dbRole)

	loginVault()
	log.Printf("Token duration: %d, Loop count: %d, Concurrency: %d\n", tokenDuration, loopCount, concurrency)

	concurrency := make(chan int, concurrency)

	if loopCount > 0 {
		wg := sync.WaitGroup{}

		wg.Add(loopCount)
		for i := 0; i < loopCount; i++ {
			go getDbCred(&wg, concurrency)
		}
		wg.Wait()
		close(concurrency)
	} else {
		for {
			if count := remaining.getCount(); count < 5000 {
				log.Println(count, " request left. Add 5000 request to go routine.")
				remaining.addCount(5000)
				for i := 0; i < 5000; i++ {
					go getDbCred(nil, concurrency)
				}
			}

			if tokenDuration < 600 {
				loginVault()
				log.Println("Vault token renewed.")
			}

			time.Sleep(1 * time.Second)
		}

	}
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
var tokenDuration int

var vaultUrl string
var vaultRole string
var dbRole string
var loopCount int
var concurrency int
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
	vaultConfig.ConfigureTLS(tlsConf)
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
	tokenDuration = secret.Auth.LeaseDuration

	vaultClient = client
}

func getDbCred(wg *sync.WaitGroup, concurrency chan int) {
	concurrency <- 0

	logical := vaultClient.Logical()

	_, err := logical.Read(fmt.Sprintf("/database/creds/%s", dbRole))
	if err != nil {
		log.Printf("Read DB credential error: %s\n", err)

	}
	<-concurrency

	if wg != nil {
		wg.Done()
	} else {
		remaining.addCount(-1)
	}
}
