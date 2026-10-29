// SPDX-License-Identifier: MIT

package server

import "net"

// NewListener creates the control-connection listener. Using the "tcp"
// network with a wildcard address (e.g. ":21" or "[::]:21") yields a
// dual-stack socket that accepts both IPv4 and IPv6 connections.
func NewListener(addr string) (net.Listener, error) {
	return net.Listen("tcp", addr)
}
