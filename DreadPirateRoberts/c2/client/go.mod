module c2/client

go 1.21

require (
	c2/common v0.0.0
	github.com/gorilla/websocket v1.5.1
)

require golang.org/x/net v0.17.0 // indirect

replace c2/common => ../common
