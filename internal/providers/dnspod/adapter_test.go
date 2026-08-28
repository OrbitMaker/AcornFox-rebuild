package dnspod

import (
	"context"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

type fixtureDoer struct {
	request *http.Request
	body    string
}

func (d *fixtureDoer) Do(request *http.Request) (*http.Response, error) {
	d.request = request
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(d.body)), Header: make(http.Header)}, nil
}

func TestListRecordsUsesOnlyFrozenReadContract(t *testing.T) {
	doer := &fixtureDoer{body: `{"Response":{"RequestId":"req-fixture","RecordCountInfo":{"TotalCount":1},"RecordList":[{"RecordId":42,"DomainId":7,"Name":"console","Type":"A","Value":"8.8.8.8","TTL":600}]}}`}
	adapter := Adapter{Endpoint: "https://fixture.invalid/", Client: doer, Clock: func() time.Time { return time.Unix(1, 0).UTC() }}
	records, err := adapter.ListRecords(context.Background(), 7, "Example.COM")
	if err != nil || len(records) != 1 || records[0].RecordID != 42 || records[0].RequestID != "req-fixture" || records[0].CreatedAt != time.Unix(1, 0).UTC() {
		t.Fatalf("records=%+v err=%v", records, err)
	}
	if doer.request.Header.Get("X-TC-Action") != ActionDescribeRecordList || doer.request.Header.Get("X-TC-Version") != APIVersion || doer.request.Header.Get("Authorization") != "" {
		t.Fatalf("unsafe DNSPod request: %#v", doer.request.Header)
	}
}

func TestListRecordsFailsClosedForPaginationAndDomainMismatch(t *testing.T) {
	for _, body := range []string{
		`{"Response":{"RequestId":"req","RecordCountInfo":{"TotalCount":2},"RecordList":[{"RecordId":42,"DomainId":7,"Name":"console","Type":"A","Value":"8.8.8.8","TTL":600}]}}`,
		`{"Response":{"RequestId":"req","RecordCountInfo":{"TotalCount":1},"RecordList":[{"RecordId":42,"DomainId":8,"Name":"console","Type":"A","Value":"8.8.8.8","TTL":600}]}}`,
		`{"Response":{"RequestId":"req","Error":{"Code":"AuthFailure.SignatureFailure","Message":"fixture failure"},"RecordCountInfo":{"TotalCount":0},"RecordList":[]}}`,
		`{"Response":{"RequestId":"req","RecordCountInfo":{"TotalCount":0},"RecordList":[{"RecordId":42,"DomainId":7,"Name":"console","Type":"A","Value":"8.8.8.8","TTL":600}]}}`,
		`{"Response":{"RecordList":[]}}`,
	} {
		doer := &fixtureDoer{body: body}
		adapter := Adapter{Endpoint: "https://fixture.invalid/", Client: doer}
		if _, err := adapter.ListRecords(context.Background(), 7, "example.com"); err == nil {
			t.Fatal("unsafe DNSPod list was accepted")
		}
	}
}
