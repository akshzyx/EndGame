package onionbalance

import (
	"github.com/stretchr/testify/assert"
	"strings"
	"testing"
)

func TestConnScannerThread(t *testing.T) {
	r := strings.NewReader(`650+HS_DESC_CONTENT line1
line2
line3
650 OK
650 HS_DESC line1
250 OK`)
	var msg1, msg2, msg3 string
	var msgCount int
	clb := func(msg string) {
		msgCount++
		if msgCount == 1 {
			msg1 = msg
		} else if msgCount == 2 {
			msg2 = msg
		} else if msgCount == 3 {
			msg3 = msg
		}
	}
	connScannerThread(r, clb)
	assert.Equal(t, 3, msgCount)
	assert.Equal(t, msg1, "650+HS_DESC_CONTENT line1\nline2\nline3")
	assert.Equal(t, msg2, "650 HS_DESC line1")
	assert.Equal(t, msg3, "250 OK")
}
