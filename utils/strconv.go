package utils

import "golang.org/x/exp/constraints"

func IntArrayToString[T constraints.Integer](arr []T) string {
	n := 0
	for ; n < len(arr); n++ {
		if arr[n] == 0 {
			break
		}
	}

	runes := make([]rune, n)
	for i := range n {
		runes[i] = rune(arr[i])
	}

	return string(runes)
}
