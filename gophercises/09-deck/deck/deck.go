//go:generate stringer -type=Suit,Value

package deck

import (
	"fmt"
	"math/rand"
	"sort"
	"strings"
	"time"
)

// Suit represents the card Suit.
type Suit int

// Seems like the sequence here is important. Spades come first.
const (
	Spade Suit = iota
	Diamond
	Club
	Heart
	Joker // Added after seeing the joker requirement.
)

// Value is the card's value.
type Value int

const (
	Ace Value = iota + 1
	Two
	Three
	Four
	Five
	Six
	Seven
	Eight
	Nine
	Ten
	Jack
	Queen
	King
)

// Card represents a playing card.
type Card struct {
	Suit
	Value
}

// String is the stringer for Card.
func (c Card) String() string {
	if c.Suit == Joker {
		return "Joker"
	}
	return fmt.Sprintf("%v of %vs", c.Value.String(), c.Suit.String())
}

// Unlike the video sI am creating a Deck type.

// Deck represents a pack of cards.
type Deck struct {
	Cards []Card
}

// String is stringer for deck and prints all deck cards.
func (d Deck) String() string {

	var sb strings.Builder
	for _, v := range d.Cards {
		sb.WriteString(fmt.Sprintf("%v\n", v.String()))
	}
	return sb.String()
}

// NewDefault generates a new deck without jokers or any options.
func NewDefault() Deck {
	var deck Deck
	for s := Spade; s <= Heart; s++ {
		for v := Ace; v <= King; v++ {
			deck.Cards = append(deck.Cards, Card{Suit: s, Value: v})
		}
	}
	return deck
}

// New generates a deck of cards with options.
// Options are in form of functions with this signature "func(Deck) Deck"
// They are executed on the deck and each transforms the deck.
func New(opts ...func(Deck) Deck) Deck {
	// Generate the cards as usual.
	var deck Deck
	for s := Spade; s <= Heart; s++ {
		for v := Ace; v <= King; v++ {
			deck.Cards = append(deck.Cards, Card{Suit: s, Value: v})
		}
	}
	// Now we need to parse opts and execute each on the deck.
	for _, opt := range opts {
		deck = opt(deck)
	}
	return deck
}

// CreateJoker returns a joker Card.
// TODO: Value of 1 for joker might not make any difference unless it's assigned
// a numerical value later in the exercise.
func CreateJoker() Card {
	return Card{Suit: Joker, Value: 1}
}

// AddJokers adds a number of jokers to the deck.
func AddJokers(n int) func(Deck) Deck {
	return func(d Deck) Deck {
		for i := 0; i < n; i++ {
			d.Cards = append(d.Cards, CreateJoker())
		}
		return d
	}
}

// Contains checks if a specific card is in the deck.
func (d Deck) Contains(c Card) bool {
	for _, v := range d.Cards {
		if v == c {
			return true
		}
	}
	return false
}

// excludeDeck removes one deck's cards from the receiver.
// This function is used internally in FilterDeck.
func (d Deck) excludeDeck(exclude Deck) Deck {
	var newDeck Deck
	// Range over the deck and remove the copy.
	for _, c := range d.Cards {
		if exclude.Contains(c) {
			continue
		}
		newDeck.Cards = append(newDeck.Cards, c)
	}
	return newDeck
}

// FilterDeck removes all cards of a deck from the other.
func FilterDeck(exclude Deck) func(Deck) Deck {
	return func(original Deck) Deck {
		return original.excludeDeck(exclude)
	}
}

// FilterCard removes all copies of a specific card from the deck.
func FilterCard(remove ...Card) func(Deck) Deck {
	return func(original Deck) Deck {
		var exclude Deck
		exclude.Cards = append(exclude.Cards, remove...)
		return original.excludeDeck(exclude)
	}
}

// We can implement the Sort interface.
// See first example here: https://golang.org/pkg/sort/#pkg-overview

// Len returns the number of cards in the deck.
func (d Deck) Len() int { return len(d.Cards) }

// Swap performs a swap on two cards in the deck.``
func (d Deck) Swap(i, j int) { d.Cards[i], d.Cards[j] = d.Cards[j], d.Cards[i] }

// Less is the comparison function used for sorting the deck.
func (d Deck) Less(i, j int) bool {

	// Lower suit has lower value.
	if d.Cards[i].Suit < d.Cards[j].Suit {
		return true
	}

	// If comparing with the same suit, go by value.
	if d.Cards[i].Suit == d.Cards[j].Suit {
		return d.Cards[i].Value < d.Cards[j].Value
	}

	// Otherwise, return false.
	return false
}

// Sort sorts the deck.
func Sort() func(Deck) Deck {
	return func(d Deck) Deck {
		sort.Sort(d)
		return d
	}
}

// Shuffle shuffles the deck (doh).
// Our shuffling going to be "craptographically" secure because we are
// using math/rand.Shuffle.
func Shuffle() func(Deck) Deck {
	return func(d Deck) Deck {
		// Remember lessons learned from 01.
		rnd := rand.New(rand.NewSource(time.Now().Unix()))
		rnd.Shuffle(d.Len(), d.Swap)
		return d
	}
}

// Multiply adds n decks to the current deck.
func Multiply(n int) func(Deck) Deck {
	return func(d Deck) Deck {
		for i := 0; i < n; i++ {
			d.Cards = append(d.Cards, NewDefault().Cards...)
		}
		return d
	}
}
