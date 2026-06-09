package ratelimit

import (
	"testing"
	"time"
)

func TestCheckAllows(t *testing.T) {
	l := New()
	if !l.Check("127.0.0.1", 5, time.Minute) {
		t.Fatal("first attempt should be allowed")
	}
}

func TestCheckBlocks(t *testing.T) {
	l := New()
	for i := 0; i < 3; i++ {
		if !l.Check("127.0.0.1", 3, time.Minute) {
			t.Fatalf("attempt %d should be allowed", i+1)
		}
	}
	if l.Check("127.0.0.1", 3, time.Minute) {
		t.Fatal("4th attempt should be blocked")
	}
}

func TestCheckSeparateAddrs(t *testing.T) {
	l := New()
	// Fill up addr1
	for i := 0; i < 3; i++ {
		l.Check("10.0.0.1", 3, time.Minute)
	}
	// addr2 should still be allowed
	if !l.Check("10.0.0.2", 3, time.Minute) {
		t.Fatal("different addr should be allowed")
	}
}

func TestClean(t *testing.T) {
	l := New()
	l.Check("127.0.0.1", 5, time.Millisecond)
	time.Sleep(10 * time.Millisecond)
	l.Clean(time.Millisecond)
	// After clean, should be allowed again
	if !l.Check("127.0.0.1", 5, time.Millisecond) {
		t.Fatal("should be allowed after clean")
	}
}
