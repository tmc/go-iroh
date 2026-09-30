package iroh

// SetMaxAdmitting sets how many incoming connections e admits at once. Call it
// before e starts accepting.
func SetMaxAdmitting(e *Endpoint, n int) { e.admissions.max = n }
