package dns_filter_server

type dns_error struct {
	msg      string
	filtered bool
}

func NewDNSError(msg string, filtered bool) *dns_error {
	return &dns_error{msg, filtered}
}

func RepackDNSError(e error, filtered bool) *dns_error {
	return &dns_error{e.Error(), filtered}
}

func (e *dns_error) Error() string {
	return e.msg
}

func (e *dns_error) Filtered() bool {
	return e.filtered
}
