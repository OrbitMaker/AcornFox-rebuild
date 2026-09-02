package main

import "testing"

func TestAcornFoxLogSegmentOrderPreservesAgentChunkOrder(t *testing.T) {
	first, err := acornFoxLogSegmentOrder(1, 2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := acornFoxLogSegmentOrder(2, 0)
	if err != nil || first >= second {
		t.Fatalf("first=%d second=%d err=%v", first, second, err)
	}
	if _, err := acornFoxLogSegmentOrder(0, 0); err == nil {
		t.Fatal("zero Agent sequence was accepted")
	}
}
