package main

import (
	"fmt"
	vault "github.com/hashicorp/vault/api"
	"gopkg.in/urfave/cli.v1"
	"io/ioutil"
	"log"
	"os"
	"sync"
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

	concurrency := make(chan int, concurrency)

	wg := sync.WaitGroup{}
	wg.Add(loopCount)
	for i := 0; i < loopCount; i++ {
		go getDbCred(&wg, concurrency)
	}
	wg.Wait()
	close(concurrency)
}

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

	vaultClient = client
}

func getDbCred(wg *sync.WaitGroup, concurrency chan int) {
	concurrency <- 0

	logical := vaultClient.Logical()

	result, err := logical.Read(fmt.Sprintf("/database/creds/%s", dbRole))
	if err != nil {
		log.Printf("Read DB credential error: %s\n", err)

	} else {
		log.Println("DB: ", result.Data)
	}
	<-concurrency
	wg.Done()
}
