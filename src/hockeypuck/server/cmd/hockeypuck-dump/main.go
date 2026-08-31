package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	"gopkg.in/tomb.v2"

	"hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/server"
	"hockeypuck/server/cmd"
)

var (
	outputDir = flag.String("path", ".", "output path")
	count     = flag.Int("count", 15000, "keys per file")
)

func main() {
	flag.Parse()
	settings := cmd.Init(false)
	cmd.HandleSignals()
	err := dump(settings)
	cmd.Die(err)
}

func dump(settings *server.Settings) error {
	policyOptions := server.PolicyOptions(settings)
	policy, err := openpgp.NewPolicy(policyOptions...)
	if err != nil {
		return err
	}
	st, err := server.DialStorage(settings, policy)
	if err != nil {
		return errors.WithStack(err)
	}
	defer st.Close()

	var t tomb.Tomb
	ch := make(chan *storage.Record)
	quit := make(chan struct{})

	t.Go(func() error {
		defer func() {
			close(quit)
			for range ch {
			}
		}() // drain if early return on error
		err = writeKeys(ch)
		if err != nil {
			return errors.WithStack(err)
		}
		return nil
	})
	t.Go(func() error {
		defer close(ch)
		_, interrupted := st.EnumerateRecords(ch, quit)
		if interrupted {
			return errors.Errorf("enumeration interrupted")
		}
		return nil
	})
	return t.Wait()
}

func writeKeys(ch chan *storage.Record) error {
	var filenum, recnum int
	f, err := os.Create(filepath.Join(*outputDir, fmt.Sprintf("hkp-dump-%04d.pgp", filenum)))
	if err != nil {
		return errors.WithStack(err)
	}
	defer f.Close()

	for record := range ch {
		if recnum >= *count {
			// close the current output file and open a new one
			f.Close()
			filenum++
			recnum = 0
			f, err = os.Create(filepath.Join(*outputDir, fmt.Sprintf("hkp-dump-%04d.pgp", filenum)))
			if err != nil {
				return errors.WithStack(err)
			}
		}

		if record.PrimaryKey != nil {
			err := openpgp.WritePackets(f, record.PrimaryKey)
			if err != nil {
				return errors.WithStack(err)
			}
		} else {
			fmt.Printf("INFO: skipping unparseable record record=%v", record.Fingerprint)
		}
		recnum++
	}
	return nil
}
