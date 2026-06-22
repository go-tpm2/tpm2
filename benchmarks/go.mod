// Isolated benchmark module: depends on go-tpm2/tpm2 (the library under test)
// and on github.com/google/go-tpm (the reference implementation we compare
// against). Kept in its own module so the comparison dependency never enters
// the library's go.mod and the benchmark files are excluded from the package's
// 100%-coverage gate.
module github.com/go-tpm2/tpm2/benchmarks

go 1.24

require (
	github.com/go-tpm2/common v0.1.0
	github.com/go-tpm2/tpm2 v0.0.0-00010101000000-000000000000
	github.com/google/go-tpm v0.9.8
)

require golang.org/x/sys v0.8.0 // indirect

replace (
	github.com/go-tpm2/common => ../../common
	github.com/go-tpm2/tpm2 => ../
)
