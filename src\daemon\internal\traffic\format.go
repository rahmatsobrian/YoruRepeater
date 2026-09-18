package traffic

import "strconv"

// strconvFormat formats a float without exponent notation and at most two
// decimals, so the UI never sees "1.234e+06".
func strconvFormat(f float64) string {
	return strconv.FormatFloat(f, 'f', 2, 64)
}
