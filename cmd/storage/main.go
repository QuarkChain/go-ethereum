package main

import (
	"fmt"
	"io"
	"os"

	"github.com/ethereum/go-ethereum/log"
	"github.com/mattn/go-colorable"
	"github.com/mattn/go-isatty"
	"github.com/spf13/cobra"
)

var (
	filename    *string
	chunkIdxLen *uint64

	verbosity *int

	chunkIdx   *uint64
	readLen    *uint64
	readMasked *bool
)

var CreateCmd = &cobra.Command{
	Use:   "create",
	Short: "Create a storage file",
	Run:   runCreate,
}

var ReadCmd = &cobra.Command{
	Use:   "read",
	Short: "Read a chunk from a storage file",
	Run:   runRead,
}

func init() {
	chunkIdxLen = CreateCmd.Flags().Uint64("len", 0, "Chunk idx len")

	filename = rootCmd.PersistentFlags().String("filename", "", "Data filename")
	verbosity = rootCmd.PersistentFlags().Int("verbosity", 3, "Logging verbosity: 0=silent, 1=error, 2=warn, 3=info, 4=debug, 5=detail")
	chunkIdx = rootCmd.PersistentFlags().Uint64("idx", 0, "Chunk idx to start/read/write")

	readLen = ReadCmd.Flags().Uint64("readlen", CHUNK_SIZE, "Bytes to read (only for unmasked read)")
	readMasked = ReadCmd.Flags().Bool("masked", false, "Read masked or not")
}

func runCreate(cmd *cobra.Command, args []string) {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(*verbosity))
	log.Root().SetHandler(glogger)

	// setup logger
	var ostream log.Handler
	output := io.Writer(os.Stderr)

	usecolor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
	if usecolor {
		output = colorable.NewColorableStderr()
	}
	ostream = log.StreamHandler(output, log.TerminalFormat(usecolor))

	glogger.SetHandler(ostream)

	_, err := Create(*filename, *chunkIdx, *chunkIdxLen, MASK_KECCAK_256)
	if err != nil {
		log.Crit("create failed", "error", err)
	}
}

func runRead(cmd *cobra.Command, args []string) {
	glogger := log.NewGlogHandler(log.StreamHandler(os.Stderr, log.TerminalFormat(false)))
	glogger.Verbosity(log.Lvl(*verbosity))
	log.Root().SetHandler(glogger)

	// setup logger
	var ostream log.Handler
	output := io.Writer(os.Stderr)

	usecolor := (isatty.IsTerminal(os.Stderr.Fd()) || isatty.IsCygwinTerminal(os.Stderr.Fd())) && os.Getenv("TERM") != "dumb"
	if usecolor {
		output = colorable.NewColorableStderr()
	}
	ostream = log.StreamHandler(output, log.TerminalFormat(usecolor))

	glogger.SetHandler(ostream)

	var err error
	var df *DataFile
	df, err = Open(*filename)
	if err != nil {
		log.Crit("open failed", "error", err)
	}

	var b []byte
	if *readMasked {
		b, err = df.ReadMasked(*chunkIdx)
	} else {
		b, err = df.ReadUnmasked(*chunkIdx, int(*readLen))
	}
	if err != nil {
		log.Crit("open failed", "error", err)
	}
	os.Stdout.Write(b)
}

// rootCmd represents the base command when called without any subcommands
var rootCmd = &cobra.Command{
	Use:   "storage",
	Short: "Storage tools",
}

func init() {
	rootCmd.AddCommand(CreateCmd)
	rootCmd.AddCommand(ReadCmd)
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
