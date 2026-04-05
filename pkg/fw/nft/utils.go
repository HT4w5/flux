package nft

import "strconv"

func v4SetName(i int) string {
	return "v4_" + strconv.Itoa(i)
}

func v6SetName(i int) string {
	return "v6_" + strconv.Itoa(i)
}

func portSetName(i int) string {
	return "port_" + strconv.Itoa(i)
}
