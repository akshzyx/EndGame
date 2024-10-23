package onionbalance

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestGetRollingSubArr(t *testing.T) {
	arr := []int{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	assert.Equal(t, []int{1, 2, 3}, getRollingSubArr(arr, 0, 3))
	assert.Equal(t, []int{4, 5, 6}, getRollingSubArr(arr, 1, 3))
	assert.Equal(t, []int{7, 8, 9}, getRollingSubArr(arr, 2, 3))
	assert.Equal(t, []int{10, 1, 2}, getRollingSubArr(arr, 3, 3))
	assert.Equal(t, []int{3, 4, 5}, getRollingSubArr(arr, 4, 3))
}
