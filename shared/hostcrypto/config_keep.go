package hostcrypto

// ConfigKeepWords returns the first words of the lines a product's parser reads. Filled in by the configuration parsers.
func ConfigKeepWords(product string) []string { return configKeepWords[product] }

var configKeepWords = map[string][]string{}
