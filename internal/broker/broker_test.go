package broker

import "testing"

func TestTailBufferBoundsMemoryAndKeepsTail(t *testing.T) {
	b := newTailBuffer(4)
	for _, part := range []string{"ab", "cdef", "gh"} {
		if _, err := b.Write([]byte(part)); err != nil {
			t.Fatal(err)
		}
	}
	if got := string(b.Bytes()); got != "efgh" {
		t.Fatalf("tail = %q", got)
	}
	if got := b.Total(); got != 8 {
		t.Fatalf("total = %d", got)
	}
	if len(b.Bytes()) > 4 {
		t.Fatal("buffer exceeded bound")
	}
}

func TestTailBufferLargeWrite(t *testing.T) {
	b := newTailBuffer(3)
	if _, err := b.Write([]byte("abcdef")); err != nil {
		t.Fatal(err)
	}
	if got := string(b.Bytes()); got != "def" {
		t.Fatalf("tail = %q", got)
	}
}
