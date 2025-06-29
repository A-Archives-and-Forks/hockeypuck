/*
   Hockeypuck - OpenPGP key server
   Copyright (C) 2012-2025 Casey Marshall and the Hockeypuck Contributors

   This program is free software: you can redistribute it and/or modify
   it under the terms of the GNU Affero General Public License as published by
   the Free Software Foundation, version 3.

   This program is distributed in the hope that it will be useful,
   but WITHOUT ANY WARRANTY; without even the implied warranty of
   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
   GNU Affero General Public License for more details.

   You should have received a copy of the GNU Affero General Public License
   along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

package pghkp

import (
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	_ "github.com/lib/pq"
	"github.com/pkg/errors"
	"golang.org/x/exp/slices"

	"hockeypuck/hkp/jsonhkp"
	hkpstorage "hockeypuck/hkp/storage"
	"hockeypuck/openpgp"
	"hockeypuck/pghkp/types"

	log "github.com/sirupsen/logrus"
)

//
// Queryer implementation
//

func (st *storage) MatchMD5(md5s []string) ([]string, error) {
	var md5In []string
	var md5Values []string
	for _, md5 := range md5s {
		// Must validate to prevent SQL injection since we're appending SQL strings here.
		_, err := hex.DecodeString(md5)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid MD5 %q", md5)
		}
		md5In = append(md5In, "'"+strings.ToLower(md5)+"'")
		md5Values = append(md5Values, "('"+strings.ToLower(md5)+"')")
	}

	sqlStr := fmt.Sprintf("SELECT rfingerprint FROM keys WHERE md5 IN (%s)", strings.Join(md5In, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []string
	defer rows.Close()
	for rows.Next() {
		var rfp string
		err := rows.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, rfp)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	// If we receive a hashquery for nonexistent digest(s), assume the ptree is stale and force an update.
	// https://github.com/hockeypuck/hockeypuck/issues/170#issuecomment-1384003238 (note 1)
	sqlStr = fmt.Sprintf("SELECT md5 FROM (values %s) as hashquery(md5) WHERE NOT EXISTS (SELECT FROM keys WHERE md5 = hashquery.md5)", strings.Join(md5Values, ","))
	rows, err = st.Query(sqlStr)
	if err == nil {
		for rows.Next() {
			var md5 string
			err := rows.Scan(&md5)
			if err == nil {
				st.Notify(hkpstorage.KeyRemovedJitter{ID: "??", Digest: md5})
			}
		}
	}

	return result, nil
}

// Resolve implements storage.Storage.
//
// Only v4 key IDs are resolved by this backend. v3 short and long key IDs
// currently won't match.
func (st *storage) Resolve(keyids []string) (_ []string, retErr error) {
	var result []string
	sqlStr := "SELECT rfingerprint FROM keys WHERE rfingerprint LIKE $1 || '%'"
	stmt, err := st.Prepare(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer stmt.Close()

	var subKeyIDs []string
	for _, keyid := range keyids {
		keyid = strings.ToLower(keyid)
		var rfp string
		row := stmt.QueryRow(keyid)
		err = row.Scan(&rfp)
		if err == sql.ErrNoRows {
			subKeyIDs = append(subKeyIDs, keyid)
		} else if err != nil {
			return nil, errors.WithStack(err)
		}
		result = append(result, rfp)
	}

	if len(subKeyIDs) > 0 {
		subKeyResult, err := st.resolveSubKeys(subKeyIDs)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		result = append(result, subKeyResult...)
	}

	return result, nil
}

func (st *storage) resolveSubKeys(keyids []string) ([]string, error) {
	var result []string
	sqlStr := "SELECT rfingerprint FROM subkeys WHERE rsubfp LIKE $1 || '%'"
	stmt, err := st.Prepare(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer stmt.Close()

	for _, keyid := range keyids {
		keyid = strings.ToLower(keyid)
		var rfp string
		row := stmt.QueryRow(keyid)
		err = row.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, rfp)
	}

	return result, nil
}

func (st *storage) MatchKeyword(search []string) ([]string, error) {
	var result []string
	stmt, err := st.Prepare("SELECT rfingerprint FROM keys WHERE keywords @@ $1::TSQUERY LIMIT $2")
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer stmt.Close()

	for _, term := range search {
		err = func() error {
			query, err := types.KeywordsTSQuery(term)
			if err != nil {
				return errors.WithStack(err)
			}
			rows, err := stmt.Query(query, 100)
			if err != nil {
				return errors.WithStack(err)
			}
			defer rows.Close()
			for rows.Next() {
				var rfp string
				err = rows.Scan(&rfp)
				if err != nil && err != sql.ErrNoRows {
					return errors.WithStack(err)
				}
				result = append(result, rfp)
			}
			err = rows.Err()
			if err != nil {
				return errors.WithStack(err)
			}
			return nil
		}()
		if err != nil {
			return nil, err
		}
	}
	return result, nil
}

// ModifiedSince returns the fingerprints of the first 100 keys modified after the reference time.
// To get another 100 keys, pass the mtime of the last key returned to a subsequent invocation.
//
// TODO: Multiple calls do not appear to work as expected, the result windows overlap.
// Are the results sorted correctly by increasing MTime? That may explain the results.
func (st *storage) ModifiedSince(t time.Time) ([]string, error) {
	var result []string
	rows, err := st.Query("SELECT rfingerprint FROM keys WHERE mtime > $1 ORDER BY mtime ASC LIMIT 100", t)
	if err != nil {
		return nil, errors.WithStack(err)
	}
	defer rows.Close()
	for rows.Next() {
		var rfp string
		err = rows.Scan(&rfp)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		result = append(result, rfp)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}
	return result, nil
}

func (st *storage) FetchKeys(rfps []string, options ...string) ([]*openpgp.PrimaryKey, error) {
	autoPreen := slices.Contains(options, hkpstorage.AutoPreen)
	if len(rfps) == 0 {
		return nil, nil
	}

	var rfpIn []string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr := fmt.Sprintf("SELECT doc, md5 FROM keys WHERE rfingerprint IN (%s)", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*openpgp.PrimaryKey
	defer rows.Close()
	for rows.Next() {
		var bufStr, sqlMD5 string
		err = rows.Scan(&bufStr, &sqlMD5)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		var pk jsonhkp.PrimaryKey
		err = json.Unmarshal([]byte(bufStr), &pk)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if pk.MD5 != sqlMD5 {
			// It is possible that the JSON MD5 field does not match the SQL MD5 field
			// This is harmless in itself since we throw away the JSON field,
			// but it may be a symptom of problems elsewhere, so log it.
			log.Warnf("inconsistent MD5 in database (sql=%s, json=%s), ignoring json", sqlMD5, pk.MD5)
		}

		rfp := openpgp.Reverse(pk.Fingerprint)
		key, err := types.ReadOneKey(pk.Bytes(), rfp)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if autoPreen {
			err = st.preen(key, pk, sqlMD5)
			if err != nil {
				continue
			}
		}
		result = append(result, key)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return result, nil
}

func (st *storage) FetchRecords(rfps []string, options ...string) ([]*hkpstorage.Record, error) {
	autoPreen := slices.Contains(options, hkpstorage.AutoPreen)
	var rfpIn []string
	for _, rfp := range rfps {
		_, err := hex.DecodeString(rfp)
		if err != nil {
			return nil, errors.Wrapf(err, "invalid rfingerprint %q", rfp)
		}
		rfpIn = append(rfpIn, "'"+strings.ToLower(rfp)+"'")
	}
	sqlStr := fmt.Sprintf("SELECT doc, md5, ctime, mtime FROM keys WHERE rfingerprint IN (%s)", strings.Join(rfpIn, ","))
	rows, err := st.Query(sqlStr)
	if err != nil {
		return nil, errors.WithStack(err)
	}

	var result []*hkpstorage.Record
	defer rows.Close()
	for rows.Next() {
		var bufStr, sqlMD5 string
		var record hkpstorage.Record
		err = rows.Scan(&bufStr, &sqlMD5, &record.CTime, &record.MTime)
		if err != nil && err != sql.ErrNoRows {
			return nil, errors.WithStack(err)
		}
		var pk jsonhkp.PrimaryKey
		err = json.Unmarshal([]byte(bufStr), &pk)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if pk.MD5 != sqlMD5 {
			// It is possible that the JSON MD5 field does not match the SQL MD5 field
			// This is harmless in itself since we throw away the JSON field,
			// but it may be a symptom of problems elsewhere, so log it.
			log.Warnf("inconsistent MD5 in database (sql=%s, json=%s), ignoring json", sqlMD5, pk.MD5)
		}

		rfp := openpgp.Reverse(pk.Fingerprint)
		key, err := types.ReadOneKey(pk.Bytes(), rfp)
		if err != nil {
			return nil, errors.WithStack(err)
		}
		if autoPreen {
			err = st.preen(key, pk, sqlMD5)
			if err != nil {
				continue
			}
		}
		record.PrimaryKey = key
		result = append(result, &record)
	}
	err = rows.Err()
	if err != nil {
		return nil, errors.WithStack(err)
	}

	return result, nil
}

var deletedKey = errors.Errorf("key deleted")

func (st *storage) preen(key *openpgp.PrimaryKey, pk jsonhkp.PrimaryKey, sqlMD5 string) error {
	if key == nil {
		log.Warnf("unparseable key material in database (fp=%s); deleting", pk.Fingerprint)
		_, err := st.Delete(pk.Fingerprint)
		if err != nil {
			log.Errorf("could not delete fp=%s", pk.Fingerprint)
			return err
		}
		return deletedKey
	}
	if len(key.SubKeys) == 0 && len(key.UserIDs) == 0 && len(key.Signatures) == 0 {
		log.Warnf("lone primary key packet in database (fp=%s); deleting", pk.Fingerprint)
		_, err := st.Delete(pk.Fingerprint)
		if err != nil {
			log.Errorf("could not delete fp=%s", pk.Fingerprint)
			return err
		}
		return deletedKey
	}
	if key.MD5 != sqlMD5 {
		log.Warnf("MD5 changed while parsing (old=%s new=%s fp=%s); cleaning", sqlMD5, key.MD5, pk.Fingerprint)
		// Beware this may cause double-updates in some circumstances
		err := st.Update(key, key.KeyID(), sqlMD5)
		if err != nil {
			log.Errorf("could not clean fp=%s", pk.Fingerprint)
			return err
		}
	}
	return nil
}
