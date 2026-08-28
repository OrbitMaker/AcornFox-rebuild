package application

import (
	"context"
	"errors"
	"testing"
)

func TestControllerCreateIsIdempotentAndReplayable(t *testing.T) {
	repository := NewMemoryRepository()
	controller := NewController(repository)
	first, err := controller.CreateApplication(context.Background(), "demo", "create-demo")
	if err != nil {
		t.Fatal(err)
	}
	second, err := controller.CreateApplication(context.Background(), "demo", "create-demo")
	if err != nil {
		t.Fatal(err)
	}
	if first.Application.ID != second.Application.ID || first.OperationID != second.OperationID || first.Event.Sequence != second.Event.Sequence {
		t.Fatalf("idempotent retry changed result: %#v %#v", first, second)
	}
	events, err := controller.ListEvents(context.Background(), first.OperationID.String(), 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].ID == "" || events[0].OperationID != first.OperationID.String() {
		t.Fatalf("persistent replay did not return the operation event: %#v", events)
	}
	after, err := controller.ListEvents(context.Background(), first.OperationID.String(), events[0].Sequence)
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != 0 {
		t.Fatalf("replay returned an already acknowledged event: %#v", after)
	}
}

func TestControllerRejectsIdempotencyKeyReuseWithDifferentInput(t *testing.T) {
	controller := NewController(NewMemoryRepository())
	if _, err := controller.CreateApplication(context.Background(), "one", "same-key"); err != nil {
		t.Fatal(err)
	}
	if _, err := controller.CreateApplication(context.Background(), "two", "same-key"); !errors.Is(err, ErrIdempotencyConflict) {
		t.Fatalf("expected idempotency conflict, got %v", err)
	}
}
