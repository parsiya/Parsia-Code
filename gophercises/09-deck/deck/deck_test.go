package deck

import (
	"reflect"
	"testing"
)

func TestCard_String(t *testing.T) {
	tests := []struct {
		name string
		c    Card
		want string
	}{
		{"1", Card{Suit: Spade, Value: Ace}, "Ace of Spades"},
		{"2", Card{Suit: Diamond, Value: Ten}, "Ten of Diamonds"},
		{"Joker1", Card{Suit: Joker, Value: Three}, "Joker"},
		{"3", Card{Suit: Joker, Value: Ace}, "Joker"},
		{"Joker2", Card{Suit: Spade, Value: Ace}, "Ace of Spades"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.c.String(); got != tt.want {
				t.Errorf("Card.String() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNewDefault(t *testing.T) {
	tests := []struct {
		name string
		want int
	}{
		{"onedeck", 52},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NewDefault(); !reflect.DeepEqual(len(got.Cards), tt.want) {
				t.Errorf("NewDefault() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCreateJoker(t *testing.T) {
	tests := []struct {
		name string
		want Card
	}{
		{"test1", Card{Suit: Joker, Value: 1}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := CreateJoker(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("CreateJoker() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterCard(t *testing.T) {
	tests := []struct {
		name  string
		cards []Card
		want  bool
	}{
		{"remove king of spades", []Card{{Suit: Spade, Value: King}}, false},
		{"remove king of diamonds", []Card{{Suit: Diamond, Value: King}}, false},
		{"remove ace of hearts", []Card{{Suit: Heart, Value: Ace}}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(FilterCard(tt.cards...)); !reflect.DeepEqual(got.Contains(tt.cards[0]), tt.want) {
				t.Errorf("FilterCard() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestFilterDeck(t *testing.T) {

	// Create a deck and shuffle it.
	deck1 := New(Shuffle())

	// Create a new deck by taking the first and last 5 cards from deck1.
	var deck2 Deck
	for i := 0; i < 5; i++ {
		deck2.Cards = append(deck2.Cards, deck1.Cards[i], deck1.Cards[deck1.Len()-i-1])
	}

	if deck2.Len() != 10 {
		t.Errorf("10 items were not added to deck2.")
	}

	t.Logf("Contents of deck2: %s", deck2.String())

	// Now create a new deck and filter deck2.

	deck3 := New(FilterDeck(deck2))

	// Nothing from deck2 should be in deck3.

	for _, c := range deck2.Cards {
		if deck3.Contains(c) {
			t.Errorf("FilterDeck failed, deck3 contains %s", c.String())
		}
	}
}

func TestMultiply(t *testing.T) {
	tests := []struct {
		name string
		n    int
		want int
	}{
		{"test1", 2, 156},
		{"test1", 0, 52},
		{"test1", 9, 520},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := New(Multiply(tt.n)); !reflect.DeepEqual(got.Len(), tt.want) {
				t.Errorf("New(Multiply(%v)) = %v, want %v", tt.n, got.Len(), tt.want)
			}
		})
	}
}
