// SPDX-License-Identifier: MIT

// Package ftp contains FTP protocol constants, helpers and data types (RFC 959).
package ftp

import "strings"

// FTP response codes (RFC 959).
const (
	// 2xx: positive completion / intermediate.
	R220ServiceReady      = 220 // Service ready for new user (greeting).
	R221Goodbye           = 221 // Service closing control connection.
	R226TransferComplete  = 226 // Closing data connection; transfer complete.
	R227PassiveMode       = 227 // Entering passive mode.
	R229ExtPassiveMode    = 229 // Entering extended passive mode.
	R230LoggedIn          = 230 // User logged in.
	R250ActionOK          = 250 // Requested file action OK.
	R257Pathname          = 257 // PATHNAME created / current directory.
	R211SystemStatus      = 211 // System status / features reply.
	R213FileStatus        = 213 // File status (SIZE/MDTM replies).
	R214HelpMessage       = 214 // Help message.
	R215SystemType        = 215 // NAME system type.
	R200CommandOK         = 200 // Command OK.
	R150FileActionPending = 150 // File status OK; opening data connection.
	R331NeedPassword      = 331 // User name OK, need password.
	R332NeedAccount       = 332 // Need account for login.
	R350FileActionPending = 350 // File action pending.

	// 4xx: transient negative.
	R421ServiceUnavailable = 421 // Service not available, closing control connection.
	R425NoDataConnection   = 425 // Cannot open data connection.
	R426TransferAborted    = 426 // Connection closed; transfer aborted.
	R450FileUnavailable    = 450 // Requested file action not taken.

	// 5xx: permanent negative.
	R500SyntaxError          = 500 // Syntax error, command unrecognized.
	R501SyntaxErrorParams    = 501 // Syntax error in parameters or arguments.
	R502NotImplemented       = 502 // Command not implemented.
	R503BadSequence          = 503 // Bad sequence of commands.
	R504NotImplementedParam  = 504 // Command not implemented for that parameter.
	R522ProtocolNotSupported = 522 // Network protocol not supported.
	R530NotLoggedIn          = 530 // Not logged in.
	R532NeedAccount          = 532 // Need account for storing files.
	R550ActionNotTaken       = 550 // Requested action not taken (file unavailable / denied).
	R551ActionAborted        = 551 // Requested action aborted: local error.
	R552ExceededStorage      = 552 // Exceeded storage allocation.
	R553FilenameNotAllowed   = 553 // File name not allowed.
)

// FTP command names.
const (
	CmdUSER = "USER"
	CmdPASS = "PASS"
	CmdQUIT = "QUIT"
	CmdNOOP = "NOOP"

	CmdPWD  = "PWD"
	CmdXPWD = "XPWD"
	CmdCWD  = "CWD"
	CmdXCWD = "XCWD"
	CmdCDUP = "CDUP"
	CmdTYPE = "TYPE"
	CmdMODE = "MODE"
	CmdSTRU = "STRU"

	CmdSYST = "SYST"
	CmdFEAT = "FEAT"
	CmdHELP = "HELP"
	CmdOPTS = "OPTS"
	CmdSIZE = "SIZE"
	CmdMDTM = "MDTM"

	CmdLIST = "LIST"
	CmdNLST = "NLST"
	CmdRETR = "RETR"

	CmdPORT = "PORT"
	CmdEPRT = "EPRT"
	CmdPASV = "PASV"
	CmdEPSV = "EPSV"

	// TLS-related commands, always rejected (plain FTP only).
	CmdAUTH = "AUTH"
	CmdPROT = "PROT"
	CmdPBSZ = "PBSZ"

	// Write commands, always rejected (read-only server).
	CmdSTOR = "STOR"
	CmdAPPE = "APPE"
	CmdSTOU = "STOU"
	CmdDELE = "DELE"
	CmdRNFR = "RNFR"
	CmdRNTO = "RNTO"
	CmdMKD  = "MKD"
	CmdXMKD = "XMKD"
	CmdRMD  = "RMD"
	CmdXRMD = "XRMD"
	CmdSITE = "SITE"

	// Recognized but not implemented.
	CmdMLSD = "MLSD"
	CmdMLST = "MLST"
	CmdREST = "REST"
)

// TransferType is the FTP transfer type set by the TYPE command.
type TransferType byte

const (
	// TypeASCII is ASCII (text) transfer mode.
	TypeASCII TransferType = 'A'
	// TypeImage is binary (image) transfer mode.
	TypeImage TransferType = 'I'
)

// Command is a parsed FTP command line: a verb and its (possibly empty) argument.
type Command struct {
	Name string // upper-cased command verb, e.g. "USER"
	Arg  string // everything after the first space, e.g. "anonymous"
}

// ParseCommand parses a raw FTP command line (with or without the trailing
// CRLF) into a Command. The verb is upper-cased; an empty line yields an
// empty Name.
func ParseCommand(line string) Command {
	line = strings.TrimRight(line, "\r\n")
	line = strings.TrimLeft(line, " \t")
	if line == "" {
		return Command{}
	}
	verb, arg, _ := strings.Cut(line, " ")
	return Command{
		Name: strings.ToUpper(verb),
		Arg:  strings.TrimLeft(arg, " "),
	}
}
