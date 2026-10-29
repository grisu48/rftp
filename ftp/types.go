package ftp

// DataMode describes how a data connection is established.
type DataMode int

const (
	// DataModeNone means no data connection has been set up yet.
	DataModeNone DataMode = iota
	// DataModeActive means the server connects out (PORT/EPRT).
	DataModeActive
	// DataModePassive means the client connects in (PASV/EPSV).
	DataModePassive
)
