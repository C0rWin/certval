Commands to run:

```
go run main.go --caFile testdata/cacerts/ca.example.com-cert.pem --certFile testdata/cacerts/ca.example.com-cert.pem --sanitizeCerts
```

and without sanitation

```
go run main.go --caFile testdata/cacerts/ca.example.com-cert.pem --certFile testdata/cacerts/ca.example.com-cert.pem
```
