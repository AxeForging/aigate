package actions

import (
	"slices"
	"strings"
	"testing"
)

func TestParsePorts(t *testing.T) {
	cases := []struct {
		in      []string
		want    []int
		wantErr bool
	}{
		{in: nil, want: nil},
		{in: []string{"3000"}, want: []int{3000}},
		{in: []string{"3000", " 8080 ", "3000"}, want: []int{3000, 8080}}, // trimmed, deduplicated
		{in: []string{"1", "65535"}, want: []int{1, 65535}},               // bounds
		{in: []string{"0"}, wantErr: true},
		{in: []string{"65536"}, wantErr: true},
		{in: []string{"http"}, wantErr: true},
		{in: []string{"3000:3000"}, wantErr: true}, // docker syntax isn't supported; say so
	}
	for _, c := range cases {
		got, err := parsePorts(c.in)
		if c.wantErr {
			if err == nil || !strings.Contains(err.Error(), "--port 3000") {
				t.Errorf("parsePorts(%q): want an error with an example, got %v", c.in, err)
			}
			continue
		}
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("parsePorts(%q) = %v, %v; want %v", c.in, got, err, c.want)
		}
	}
}
