package utils

func KeyLen(k string) bool {
	return len(k) == 32
}

func KeyPhrase() string {
	return "AllYourDataAreBelongToAES256Bits"
}
