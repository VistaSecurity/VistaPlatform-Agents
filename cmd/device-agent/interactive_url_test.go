package main

import (
	"io"
	"os"
	"strings"
	"testing"
	"time"
)

// withPrompt runs fn with stdin holding input and returns what it printed.
// It fails the test if fn has not returned within the timeout, which is what a
// prompt that never gives up on empty input does.
func withPrompt(t *testing.T, input string, fn func()) string {
	t.Helper()
	inR, inW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	outR, outW, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	oldIn, oldOut := os.Stdin, os.Stdout
	os.Stdin, os.Stdout = inR, outW
	t.Cleanup(func() { os.Stdin, os.Stdout = oldIn, oldOut })
	if _, err := io.WriteString(inW, input); err != nil {
		t.Fatal(err)
	}
	inW.Close()

	printed := make(chan string, 1)
	go func() {
		b, _ := io.ReadAll(outR)
		printed <- string(b)
	}()
	done := make(chan struct{})
	go func() {
		fn()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		os.Stdout = oldOut
		outW.Close()
		t.Fatalf("setup did not return on empty input; it printed:\n%s", <-printed)
	}
	os.Stdout = oldOut
	outW.Close()
	return <-printed
}

// There is no hosted platform: an empty answer is not a default URL but a
// question asked again, and the end of input cancels setup without contacting
// anything.
func TestInteractiveSetupHasNoDefaultPlatformURL(t *testing.T) {
	out := withPrompt(t, "\n", func() { _, _, _, _ = runInteractiveSetup("") })
	if strings.Contains(out, "Testing connectivity") {
		t.Fatalf("an empty URL was replaced by a default and contacted:\n%s", out)
	}
	if !strings.Contains(out, "The Vista Platform URL is required: it is the address of your own Vista Platform console, as shown in your browser.") {
		t.Errorf("an empty URL is not refused with the reason:\n%s", out)
	}
	if strings.Count(out, "Enter the Vista Platform URL") != 2 {
		t.Errorf("the URL is not asked for again after an empty answer:\n%s", out)
	}
	if !strings.Contains(out, "Setup cancelled: no Vista Platform URL given.") {
		t.Errorf("the end of input does not cancel setup:\n%s", out)
	}
	if strings.Contains(out, "(default:") {
		t.Errorf("the prompt still offers a default:\n%s", out)
	}
}
