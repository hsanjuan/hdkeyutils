package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"strconv"
	"strings"

	"github.com/hsanjuan/mhdw/hdwrap"
	cli "github.com/urfave/cli"
)

const defaultSeed = "seed.hex"

var seedFlag = cli.StringFlag{
	Name:  "seed",
	Usage: "path to seed file",
	Value: defaultSeed,
}

var formatFlag = cli.StringFlag{
	Name:  "format",
	Usage: "output format: btc, zec, eth or dcr",
	Value: "btc",
}

func main() {
	app := cli.NewApp()
	app.Usage = "A command line utility for manipulating HD wallet keys"
	app.Version = "0.0.2"
	app.Commands = []cli.Command{
		seedCmd,
		privKeyCmd,
		pubKeyCmd,
	}
	if err := app.Run(os.Args); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

var seedCmd = cli.Command{
	Name:  "seed",
	Usage: "utilities to generate and handle multipurpose key-seeds",
	Subcommands: []cli.Command{
		genSeedCmd,
		decodeSeedCmd,
		encodeSeedCmd,
	},
}

var genSeedCmd = cli.Command{
	Name:  "gen",
	Usage: "generate a new seed (private key)",
	Description: `
This command generates a new random seed which can be used to build HD wallets
for different cryptocurrencies and further derivate addresses and private keys.

You can include any random input as an argument to the command. This will be
used along with the values provided by the randomness source.

The generated seed in a new file. A mnemonic 65-word representation of the seed
will be printed out and can be used for offline backup. This list of words
can be converted into a seed file again witht he "seed decode-words <words>"
command.
`,
	ArgsUsage: "<additional randomness>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "randsrc",
			Usage: "filename of alternative randomness source",
		},
		cli.StringFlag{
			Name:  "output",
			Usage: "name of seed file",
			Value: defaultSeed,
		},
		cli.BoolFlag{
			Name:  "overwrite",
			Usage: "replace any existing seed files",
		},
		cli.IntFlag{
			Name:  "randbytes",
			Usage: "number of bytes to reed from randomness source",
			Value: 8192,
		},
		cli.BoolFlag{
			Name:  "quiet,q",
			Usage: "only print mnemonic seed",
		},
		cli.BoolFlag{
			Name:  "no-words",
			Usage: "do not print mnemonic seed output",
		},
		cli.IntFlag{
			Name:  "words-per-line",
			Usage: "Mnemonic words per line",
			Value: 6,
		},
	},
	Action: func(c *cli.Context) error {
		var r io.Reader = rand.Reader
		q := c.Bool("quiet")
		if randsrc := c.String("randsrc"); randsrc != "" {
			fi, err := os.Open(randsrc)
			if err != nil {
				return err
			}
			defer fi.Close()
			r = fi
		}

		userRandom := bytes.NewBufferString(strings.Join(c.Args(), ""))

		seed, err := hdwrap.GenerateCustom(c.Int("randbytes"), r, userRandom.Bytes())
		if err != nil {
			return fmt.Errorf("error generating seed: %s, err")
		}

		output := c.String("output")
		err = seed.WriteToFile(output, c.Bool("overwrite"))
		if err != nil {
			return err
		}
		if !q {
			fmt.Printf("Seed has been written to \"%s\"\n", output)
		}

		if c.Bool("no-words") {
			return nil
		}

		// Create the private key from the seed we generated
		if !q {
			fmt.Println(`
This is the mnemonic representation of the seed that is used to build your
private key and your HD wallets. Keep it safe!`)

			fmt.Println(`
-------------------------------------------------------------------------`)
			seed.PrintMnemonic(c.Int("words-per-line"))

			fmt.Println(`
-------------------------------------------------------------------------`)
			fmt.Println()
		} else {
			seed.PrintMnemonic(c.Int("words-per-line"))
		}
		return nil
	},
}

var decodeSeedCmd = cli.Command{
	Name:  "decode-words",
	Usage: "create a seed file from a mnemonic representation",
	Description: `
This commands writes a seed file given a valid list of words representing the
nmemonic encoding of the original seed.
`,
	ArgsUsage: "<33 words...>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "output",
			Usage: "name of output seed file",
			Value: "seed.hex",
		},
		cli.BoolFlag{
			Name:  "overwrite",
			Usage: "replace any existing seed files",
		},
	},
	Action: func(c *cli.Context) error {
		words := strings.Join(c.Args(), " ")
		seed, err := hdwrap.NewSeedFromWords(words)
		if err != nil {
			return err
		}
		output := c.String("output")
		err = seed.WriteToFile(output, c.Bool("overwrite"))
		if err != nil {
			return err
		}
		fmt.Println("Seed correctly imported to", output)
		return nil
	},
}

var encodeSeedCmd = cli.Command{
	Name:  "encode-words",
	Usage: "print the mnemonic representation of a seed",
	Description: `
This commands prints a mnemonic representation of a seed. This is a list of
64 words plus an extra one which acts as a checksum.

It can be done to easily backup a key on paper, for example.
`,
	ArgsUsage: " ",
	Flags: []cli.Flag{
		seedFlag,
		cli.IntFlag{
			Name:  "words-per-line",
			Usage: "number of words to print per line",
			Value: 6,
		},
	},
	Action: func(c *cli.Context) error {
		seed, err := hdwrap.NewSeedFromFile(c.String("seed"))
		if err != nil {
			return err
		}
		seed.PrintMnemonic(c.Int("words-per-line"))
		return nil
	},
}

var privKeyCmd = cli.Command{
	Name:  "priv",
	Usage: "tools for working with HD master/derived private keys",
	Subcommands: []cli.Command{
		getMasterPrivCmd,
		getChildPrivKeyCmd,
	},
}

var getMasterPrivCmd = cli.Command{
	Name:  "getmasterpriv",
	Usage: "create the a master private key from the given seed",
	Description: `
This command prints an HD wallet private key given a generation seed. The
output is specific to the chosen cryptocurrency and may not be compatible
among different ones.

Given the same seed and output format, the result is always the same.
`,
	ArgsUsage: " ",
	Flags: []cli.Flag{
		seedFlag,
		formatFlag,
		cli.BoolFlag{
			Name:  "testnet",
			Usage: "produce keyout for testnet usage",
		},
	},
	Action: func(c *cli.Context) error {
		format := c.String("format")

		k, err := makeKeyFromSeed(
			format, c.String("seed"), c.Bool("testnet"))
		if err != nil {
			return err
		}

		masterpriv, err := k.GetMasterPriv()
		if err != nil {
			return err
		}
		fmt.Print(masterpriv)
		return nil
	},
}

var getChildPrivKeyCmd = cli.Command{
	Name:  "child",
	Usage: "derive a child private key",
	Description: `
This command derives a child private key from the given seed and format
and prints it out. This can be imported into the different
cryptocurrency wallets. See the README for more information.
`,
	ArgsUsage: "<index>",
	Flags: []cli.Flag{
		seedFlag,
		formatFlag,
		cli.BoolFlag{
			Name:  "testnet",
			Usage: "produce keys for testnet usage",
		},
	},
	Action: func(c *cli.Context) error {
		format := c.String("format")

		if len(c.Args()) != 1 {
			return fmt.Errorf("must pass the derivation index")
		}

		i, err := strconv.Atoi(c.Args().First())
		if err != nil {
			return err
		}

		k, err := makeKeyFromSeed(
			format, c.String("seed"), c.Bool("testnet"))
		if err != nil {
			return err
		}

		childpriv, err := k.GetChildPrivKey(i)
		if err != nil {
			return err
		}

		fmt.Println(childpriv)
		return nil
	},
}

var pubKeyCmd = cli.Command{
	Name:  "pub",
	Usage: "tools for working with HD public keys and addresses",
	Subcommands: []cli.Command{
		getMasterPubCmd,
		getChildPubKeyCmd,
	},
}

var getMasterPubCmd = cli.Command{
	Name:  "getmasterpub",
	Usage: "obtain a master public key from the given seed",
	Description: `
This command prints an HD wallet public key given the key generation seed. The
output is specific to the chosen cryptocurrency and may not be compatible
among different ones.

Given the same seed and output format, the result is always the same.
`,
	ArgsUsage: " ",
	Flags: []cli.Flag{
		seedFlag,
		formatFlag,
		cli.BoolFlag{
			Name:  "testnet",
			Usage: "produce key for testnet usage",
		},
	},
	Action: func(c *cli.Context) error {
		format := c.String("format")

		k, err := makeKeyFromSeed(format, c.String("seed"), c.Bool("testnet"))
		if err != nil {
			return err
		}

		masterpub, err := k.GetMasterPub()
		if err != nil {
			return err
		}
		fmt.Print(masterpub)
		return nil
	},
}

var getChildPubKeyCmd = cli.Command{
	Name:  "child",
	Usage: "derive a child public key",
	Description: `
This command derives a child public key and formats it as a payment address.

The command can take a -seed (default) or a -pubkey argument. When providing a
master public key, it should be formatted for the desired cryptocurrency.
Otherwise, the generated address will not work.

Given the same seed or public key, the same derivation index and format,
the resulting address is always the same.
`,
	ArgsUsage: "<index>",
	Flags: []cli.Flag{
		cli.StringFlag{
			Name:  "pubkey",
			Usage: "a master public key",
			Value: "",
		},
		seedFlag,
		formatFlag,
		cli.BoolFlag{
			Name:  "testnet",
			Usage: "print testnet addrs",
		},
	},
	Action: func(c *cli.Context) error {
		format := c.String("format")

		if len(c.Args()) != 1 {
			return fmt.Errorf("must pass in the derivation index")
		}

		i, err := strconv.Atoi(c.Args().First())
		if err != nil {
			return err
		}

		testnet := c.Bool("testnet")
		var k hdwrap.Key
		if pubkey := c.String("pubkey"); pubkey != "" {
			k, err = makeKeyFromPubKey(format, pubkey, testnet)
			if err != nil {
				return err
			}
		} else {
			k, err = makeKeyFromSeed(format, c.String("seed"), testnet)
			if err != nil {
				return err
			}
		}

		childpriv, err := k.GetChildPubKey(i)
		if err != nil {
			return err
		}

		fmt.Println(childpriv)
		return nil
	},
}

func makeKeyFromPubKey(format, pubkey string, testnet bool) (hdwrap.Key, error) {
	k := hdwrap.EmptyKeyStr(format)
	err := k.FromString(pubkey, false)
	if err != nil {
		return nil, err
	}
	k.SetTestNet(testnet)
	return k, nil
}

func makeKeyFromPrivKey(format, pkeyfile string, testnet bool) (hdwrap.Key, error) {
	keyBytes, err := ioutil.ReadFile(pkeyfile)
	if err != nil {
		return nil, err
	}
	k := hdwrap.EmptyKeyStr(format)
	err = k.FromString(string(keyBytes), true)
	if err != nil {
		return nil, err
	}
	k.SetTestNet(testnet)
	return k, nil
}

func makeKeyFromSeed(format, seedfile string, testnet bool) (hdwrap.Key, error) {
	seed, err := hdwrap.NewSeedFromFile(seedfile)
	if err != nil {
		return nil, err
	}
	k := hdwrap.EmptyKeyStr(format)
	err = k.FromSeed(seed)
	if err != nil {
		return nil, err
	}
	k.SetTestNet(testnet)
	return k, nil
}
