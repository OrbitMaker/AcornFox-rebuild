package cli

import "flag"

// parseFlags parses a FlagSet allowing flags and positional arguments to be
// interspersed (the standard flag package stops at the first non-flag token).
// It returns the collected positional arguments. Flags that appear after
// positionals are still applied.
func parseFlags(fs *flag.FlagSet, args []string) ([]string, error) {
	var positionals []string
	rest := args
	for {
		if err := fs.Parse(rest); err != nil {
			return nil, err
		}
		rest = fs.Args()
		if len(rest) == 0 {
			break
		}
		// The first element is a positional (flag.Parse stopped on it); keep it
		// and continue parsing the remainder for more flags.
		positionals = append(positionals, rest[0])
		rest = rest[1:]
	}
	return positionals, nil
}
