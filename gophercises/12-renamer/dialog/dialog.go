package dialog

import (
	"fmt"
	"strings"
)

// Dialog represents a text-based multiple-choice dialog.
type Dialog struct {
	// The text of the choices, one per string.
	Choices []string
	// The question.
	Question string
}

// AddChoice adds the input string as a choice to the dialog.
func (d *Dialog) AddChoices(c []string) {
	d.Choices = append(d.Choices, c...)
}

// Render returns a string that can be printed to display the dialog.
func (d Dialog) Render() string {
	var sb strings.Builder
	sb.WriteString(d.Question + "\n")
	for i := range d.Choices {
		sb.WriteString(fmt.Sprintf("%d - %s", i, d.Choices[i]))
		sb.WriteString("\n")
	}
	sb.WriteString("Enter -1 to quit:\n")
	return sb.String()
}

// Display print the dialog to os.Stdout.
func (d Dialog) Display() {
	fmt.Println(d.Render())
}

// Start prints the dialog to command line and reads user input.
// It will return user's choice if valid, if not valid, it will keep retrying.
func (d Dialog) Start() int {
	d.Display()
	var c int
	for {
		_, err := fmt.Scanln(&c)
		if err != nil {
			fmt.Println("Invalid choice, please try again.")
			continue
		}
		if c == -1 {
			return c
		}
		if c < 0 || c >= len(d.Choices) {
			fmt.Println("Invalid choice, please try again.")
			fmt.Printf("Choice should be between 0 and %d - you entered %d.\n", len(d.Choices)-1, c)
			continue
		}
		return c
	}
}
