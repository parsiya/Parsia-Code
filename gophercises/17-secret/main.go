package main

import (
	"fmt"
	"os"

	"github.com/parsiya/Parsia-Code/gophercises/17-secret/keystore"
	"github.com/urfave/cli"
)

var (
	// Variable to hold subcommands.
	cmds []cli.Command
)

// Subcommands can be processed in init.
func init() {

	// Defining subcommands.
	cmds = []cli.Command{
		{
			// Name of subcommand.
			Name: "create",
			// Aliases (similar to alternate flags) stored in a string slice.
			Aliases: []string{"c"},
			// Usage text - using `` to create placeholders is not supported here.
			Usage: "Create a new keystore.\n\tsecret create [filename] [encryptionKey]",
			// Function to call when this sub command is activated.
			// Similar to app.Action, this function should be of type.
			// cli.ActionFunc == func (*cli.Context) error.
			Action: create,
		},
		{
			Name:    "set",
			Aliases: []string{"s", "add"},
			Usage:   "Set a key/value pair in the keystore.\n\tsecret set [filename] [encryptionKey] [key] [value]",
			Action:  set,
		},
		{
			Name:    "get",
			Aliases: []string{"g", "retrieve"},
			Usage:   "Get the value of a key from the keystore.\n\tsecret get [filename] [encryptionKey] [key]",
			Action:  get,
		},
		{
			Name:    "del",
			Aliases: []string{"d", "delete"},
			Usage:   "Delete a key from the keystore.\n\tsecret del [filename] [encryptionKey] [key]",
			Action:  del,
		},
		{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "List all keys in the keystore.\n\tsecret list [filename] [encryptionKey]",
			Action:  list,
		},
	}
}

func main() {

	// ********************
	// Start cli options.
	// Create a new app.
	app := cli.NewApp()

	// Set name of the program.
	app.Name = "secret"

	// Set application usage.
	app.Usage = "secret is simple encrypted keystore."

	// Hide version in usage.
	app.HideVersion = true

	// Set subcommands.
	app.Commands = cmds

	// Called if no arguments are provided at runtime.
	// Expects type cli.ActionFunc == "func (*cli.Context) error".
	app.Action = noArgs

	// End cli options.

	// Run the app
	app.Run(os.Args)
}

// noArgs will run if no arguments are provided
func noArgs(c *cli.Context) error {
	// Print app usage
	cli.ShowAppHelp(c)

	// It's possible to change the return status code and error here
	// cli.NewExitError creates a a new error and the return status code for
	// the application.
	return cli.NewExitError("No commands provided.", 2)
}

// create instantiates a new keystore.
func create(c *cli.Context) error {
	// Check for arguments after the subcommand
	if c.Args().Present() && c.NArg() == 2 {
		// Get the next argument. We can also use c.Args().Get(0)
		path := c.Args().Get(0)
		encKey := c.Args().Get(1)
		if _, err := keystore.MakeKeyStore(encKey, path); err != nil {
			return cli.NewExitError(err.Error(), 3)
		}
		fmt.Printf("Keystore created at %s.", path)
		return nil
	}
	// If there are no arguments, show help for that specific subcommands
	// and then return with an error.
	cli.ShowSubcommandHelp(c)
	return cli.NewExitError("Not enough arguments.", 3)
}

// set sets a key/value pair and adds it to the keystore (or updates it).
func set(c *cli.Context) error {
	if c.Args().Present() && c.NArg() == 4 {
		path := c.Args().Get(0)
		encKey := c.Args().Get(1)
		key := c.Args().Get(2)
		val := c.Args().Get(3)

		ks, err := keystore.GetKeyStore(encKey, path)
		if err != nil {
			return cli.NewExitError(err.Error(), 3)
		}

		if err := ks.Set(key, val); err != nil {
			return cli.NewExitError(err.Error(), 3)
		}

		fmt.Printf("Added %s to keystore.\n", key)
		fmt.Print(ks)
		return nil
	}
	cli.ShowSubcommandHelp(c)
	return cli.NewExitError("Not enough arguments.", 3)
}

// get opens the keystore and returns the value of the key.
func get(c *cli.Context) error {
	if c.Args().Present() && c.NArg() == 3 {
		path := c.Args().Get(0)
		encKey := c.Args().Get(1)
		key := c.Args().Get(2)

		ks, err := keystore.GetKeyStore(encKey, path)
		if err != nil {
			return cli.NewExitError(err.Error(), 3)
		}

		val, err := ks.Get(key)
		if err != nil {
			return cli.NewExitError(err.Error(), 3)
		}

		fmt.Printf("Value of %s key is: %s.\n", key, val)
		fmt.Print(ks)
		return nil
	}
	cli.ShowSubcommandHelp(c)
	return cli.NewExitError("Not enough arguments.", 3)
}

// del deletes a key from the keystore.
func del(c *cli.Context) error {
	if c.Args().Present() && c.NArg() == 3 {
		path := c.Args().Get(0)
		encKey := c.Args().Get(1)
		key := c.Args().Get(2)

		ks, err := keystore.GetKeyStore(encKey, path)
		if err != nil {
			return cli.NewExitError(err.Error(), 3)
		}

		ks.Delete(key)
		fmt.Printf("Key %s (if exists) deleted from the keystore.\n", key)
		fmt.Print(ks)
		return nil
	}
	cli.ShowSubcommandHelp(c)
	return cli.NewExitError("Not enough arguments.", 3)
}

// list returns all keys in the keystore.
func list(c *cli.Context) error {
	if c.Args().Present() && c.NArg() == 2 {
		path := c.Args().Get(0)
		encKey := c.Args().Get(1)

		ks, err := keystore.GetKeyStore(encKey, path)
		if err != nil {
			return cli.NewExitError(err.Error(), 3)
		}

		keys := ks.List()
		fmt.Println("Keys in the keystore")
		for _, k := range keys {
			fmt.Println(k)
		}
		return nil
	}
	cli.ShowSubcommandHelp(c)
	return cli.NewExitError("Not enough arguments.", 3)
}
