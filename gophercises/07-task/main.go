package main

import (
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/olekukonko/tablewriter"

	"github.com/urfave/cli"
)

var (
	// Variable to hold subcommands.
	cmds []cli.Command

	// BoltDB.
	db *Database

	// Task list table header.
	taskListHeader = []string{"Number", "Time Added", "Task"}

	// Task completed table table header.
	taskDoneHeader = []string{"Number", "Time Completed", "Task"}

	// Holds the current tasks. Updated after each list command.
	currentTasks []Task
)

const (
	dbFile     = "task.db"
	openBucket = "open"
	doneBucket = "done"
)

// Subcommands can be processed in init.
func init() {
	// ********************
	// Open DB
	var err error
	db, err = NewDB(dbFile, []byte(openBucket), []byte(doneBucket))
	if err != nil {
		panic(fmt.Errorf("open database: %v", err))
	}
	// End BoltDB
	// ********************

	// Defining subcommands.
	cmds = []cli.Command{
		{
			// Name of subcommand.
			Name: "add",
			// Aliases (similar to alternate flags) stored in a string slice.
			Aliases: []string{"a"},
			// Usage text - using `` to create placeholders is not supported here.
			Usage: "Add a new task to your TODO list.",
			// Function to call when this sub command is activated.
			// Similar to app.Action, this function should be of type.
			// cli.ActionFunc == func (*cli.Context) error.
			Action: add,
		},
		{
			Name:    "do",
			Aliases: []string{"d"},
			Usage:   "Mark a task on your TODO list as complete.",
			Action:  do,
		},
		{
			Name:    "list",
			Aliases: []string{"l"},
			Usage:   "List all incomplete tasks.",
			Action:  list,
		},
		{
			Name:    "completed",
			Aliases: []string{"c", "done"},
			Usage:   "List all completed tasks.",
			Action:  completed,
		},
		{
			Name:    "rm",
			Aliases: []string{"r"},
			Usage:   "Remove and incomplete task from list.",
			Action:  delete,
		},
	}
}

func main() {

	// ********************
	// Start cli options.
	// Create a new app.
	app := cli.NewApp()

	// Set name of the program.
	app.Name = "task"

	// Set application usage.
	app.Usage = "task is a CLI for managing your TODOs."

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

// add adds a task to list.
func add(c *cli.Context) error {
	// Check for arguments after the subcommand
	if c.Args().Present() {
		// Get the next argument. WE can also use c.Args().Get(0)
		taskText := c.Args().First()

		if err := db.AddTask(taskText, time.Now()); err != nil {
			return cli.NewExitError(err, 3)
		}
		fmt.Printf("Added \"%v\" to your task list.\n", taskText)
		// Print new tasks.
		list(c)
		return nil
	}
	// If there are no arguments, show help for that specific subcommands
	// and then return with an error.
	cli.ShowSubcommandHelp(c)
	return cli.NewExitError("No task provided.", 3)
}

// do completes a task.
func do(c *cli.Context) error {
	currentTasks = db.ListOpenTasks()
	if len(currentTasks) == 0 {
		return cli.NewExitError("Task list is empty, add some tasks first.", 3)
	}
	// Check for arguments after the subcommand.
	if c.Args().Present() {
		// Get next argument (the index+1).
		taskIndex, err := strconv.Atoi(c.Args().First())
		if err != nil || taskIndex > len(currentTasks) || taskIndex == 0 {
			list(c)
			return cli.NewExitError(
				fmt.Sprintf("Invalid index entered: %v\nIndex should be in range of 1 to %v.",
					c.Args().First(), len(currentTasks)), 3)
		}
		// Do -- to get the currentTasks index.
		taskIndex--
		if err := db.DoTask(currentTasks[taskIndex].Key, time.Now()); err != nil {
			return cli.NewExitError(err, 3)
		}
		fmt.Printf("You have completed the \"%v\" task.\n", currentTasks[taskIndex].Text)
		list(c)
		return nil
	}
	// Show scan subcommand help
	cli.ShowSubcommandHelp(c)
	return cli.NewExitError("No task provided.", 3)
}

// list prints out all remaining tasks.
func list(c *cli.Context) error {
	currentTasks = db.ListOpenTasks()
	if len(currentTasks) == 0 {
		return cli.NewExitError("List is empty.", 3)
	}
	fmt.Println("Listing all tasks:")
	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(taskListHeader)
	for k, v := range currentTasks {
		// key+1 to start tasks from 1. Remember to key-1 in do or delete.
		table.Append([]string{strconv.Itoa(k + 1), v.Key, v.Text})
	}
	fmt.Println()
	table.Render()
	return nil
}

// completed prints out all completed tasks for last n hours (default: 24).
func completed(c *cli.Context) error {

	// Default duration.
	dr := 24

	// If an argument is provided, check it for validity and then use it.
	if c.Args().Present() {
		var err error
		dr, err = strconv.Atoi(c.Args().First())
		if err != nil || dr <= 1 {
			return cli.NewExitError(
				fmt.Sprintf("Entered invalid duration: %v.", dr), 3)
		}
	}
	doneTasks := db.ListCompletedTasks(dr)
	if len(doneTasks) == 0 {
		return cli.NewExitError(fmt.Errorf("Found no completed tasks in the last %v hours.", dr), 3)
	}

	table := tablewriter.NewWriter(os.Stdout)
	table.SetHeader(taskDoneHeader)
	for k, v := range doneTasks {
		// key+1 to start tasks from 1.
		table.Append([]string{strconv.Itoa(k + 1), v.Key, v.Text})
	}
	fmt.Println()
	fmt.Printf("You have finished the following tasks in the last %v hour(s):\n", dr)
	table.Render()

	return nil
}

// delete removes an uncompleted task.
func delete(c *cli.Context) error {
	currentTasks = db.ListOpenTasks()
	if len(currentTasks) == 0 {
		return cli.NewExitError("Task list is empty, add some tasks first.", 3)
	}
	// Check for arguments after the subcommand.
	if c.Args().Present() {
		// Get next argument (the index+1).
		taskIndex, err := strconv.Atoi(c.Args().First())
		if err != nil || taskIndex > len(currentTasks) || taskIndex == 0 {
			list(c)
			return cli.NewExitError(
				fmt.Sprintf("Invalid index entered: %v\nIndex should be in range of 1 to %v.",
					c.Args().First(), len(currentTasks)), 3)
		}
		// Do -- to get the currentTasks index.
		taskIndex--
		if err := db.DeleteTask(currentTasks[taskIndex].Key); err != nil {
			return cli.NewExitError(err, 3)
		}
		fmt.Printf("You have deleted the \"%v\" task.\n", currentTasks[taskIndex].Text)
		list(c)
		return nil
	}
	// Show scan subcommand help
	cli.ShowSubcommandHelp(c)
	return cli.NewExitError("No task provided.", 3)
}
