package notifications

import (
	"encoding/json"
	"os"
	"reflect"
	"testing"
)

func TestTerminalEventFixtures(t *testing.T) {
	for _, fixture := range []string{"build-terminal", "flash-terminal"} {
		t.Run(fixture, func(t *testing.T) {
			data, err := os.ReadFile("testdata/" + fixture + ".json")
			if err != nil {
				t.Fatal(err)
			}
			var event TerminalEvent
			if err := json.Unmarshal(data, &event); err != nil {
				t.Fatal(err)
			}
			if event.APIVersion != APIVersion || event.ID == "" || (event.Build == nil) == (event.Flash == nil) {
				t.Fatal("invalid event envelope")
			}
			if event.Build != nil && event.Type != BuildTerminal || event.Flash != nil && event.Type != FlashTerminal {
				t.Fatal("event subject does not match type")
			}
			encoded, err := json.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			var original, roundtrip any
			if err := json.Unmarshal(data, &original); err != nil {
				t.Fatal(err)
			}
			if err := json.Unmarshal(encoded, &roundtrip); err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(original, roundtrip) {
				t.Fatal("event fixture fields were dropped or renamed")
			}
			if len(encoded) > MaxPayloadBytes {
				t.Fatal("fixture exceeds payload limit")
			}
		})
	}
}
