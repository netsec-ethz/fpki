package db

import (
	"context"
	"encoding/hex"
	"fmt"
	"math/big"
	"math/rand"
	"strings"
	"sync"
	"time"
)

func DeletemeDropAllNodes(db DB) error {
	c := db.(*mysqlDB)
	_, err := c.db.Exec("DELETE FROM nodes")
	return err
}

func DeletemeCreateNodes(db DB, count int) error {
	c := db.(*mysqlDB)
	_, err := c.db.Exec("ALTER TABLE `nodes` DISABLE KEYS")
	if err != nil {
		return fmt.Errorf("disabling keys: %w", err)
	}
	blob, err := hex.DecodeString("deadbeef")
	if err != nil {
		panic("logic error")
	}
	for i := 0; i < count; i++ {
		_, err = c.db.Exec("INSERT INTO nodes VALUES(?,?)", i, blob)
		if err != nil {
			return err
		}
		if i%100 == 0 {
			fmt.Printf("%d/%d\n", i, count)
		}
	}
	_, err = c.db.Exec("ALTER TABLE `nodes` ENABLE KEYS")
	if err != nil {
		return fmt.Errorf("enabling keys: %w", err)
	}
	return nil
}

func DeletemeCreateNodesBulk(db DB, count int) error {
	c := db.(*mysqlDB)
	// _, err := c.db.Exec("ALTER TABLE `nodes` DROP INDEX PRIMARY")
	// if err != nil {
	// 	return fmt.Errorf("disabling keys: %w", err)
	// }
	_, err := c.db.Exec("LOCK TABLES nodes WRITE;")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("SET autocommit=0")
	if err != nil {
		return err
	}

	blob, err := hex.DecodeString("deadbeef")
	if err != nil {
		panic("logic error")
	}
	// stmt, err := c.db.Prepare("INSERT IGNORE INTO nodes (idnodes,value) VALUES(?,?)")
	stmt, err := c.db.Prepare("INSERT IGNORE INTO nodes (value) VALUES(?)")
	if err != nil {
		panic("logic error")
	}
	for i := 0; i < count; i++ {
		// _, err = c.db.Exec("INSERT IGNORE INTO nodes VALUES(?,?)", i, blob)
		// _, err = c.db.Exec("INSERT INTO nodes (value) VALUES(?)", blob)
		_, err = stmt.Exec(blob)
		if err != nil {
			return err
		}
		if i%1000 == 0 {
			fmt.Printf("%d/%d\n", i, count)
		}
	}

	_, err = c.db.Exec("COMMIT")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("UNLOCK TABLES")
	if err != nil {
		return err
	}
	return nil
}

func DeletemeCreateNodesBulk2(db DB, count int) error {
	var err error
	c := db.(*mysqlDB)
	_, err = c.db.Exec("LOCK TABLES nodes WRITE;")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("SET autocommit=0")
	if err != nil {
		return err
	}
	// _, err = c.db.Exec("ALTER TABLE `nodes` DISABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("disabling keys: %w", err)
	// }

	blob, err := hex.DecodeString("deadbeef")
	if err != nil {
		panic("logic error")
	}
	// prepare in chunks of 1000 records
	N := 1000
	repeatedStmt := "INSERT INTO nodes (value) VALUES " + repeatStmt(N, 1)
	// fmt.Printf("Using repeated statement:\n%s\n", repeatedStmt)
	stmt, err := c.db.Prepare(repeatedStmt)
	if err != nil {
		panic("logic error: " + err.Error())
	}
	execPreparedStmt := func() error {
		// create the N records slice
		data := make([]interface{}, N) // 1 elements per record ()
		for j := 0; j < N; j++ {
			data[j] = blob
		}
		_, err = stmt.Exec(data...)
		return err
	}
	// hash := big.Int{}
	// hash.Bits()
	for i := 0; i < count/N; i++ {
		err = execPreparedStmt()
		if err != nil {
			return err
		}
		if i%100 == 0 {
			fmt.Printf("%d/%d\n", i*N, N*count/N)
		}
	}
	// TODO(juagargi) insert the count%N remaining records

	// _, err = c.db.Exec("ALTER TABLE `nodes` ENABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("enabling keys: %w", err)
	// }
	_, err = c.db.Exec("COMMIT")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("UNLOCK TABLES")
	if err != nil {
		return err
	}
	return nil
}

var initialSequentialHash = *((&big.Int{}).Exp(big.NewInt(2), big.NewInt(200), nil))

// - inserts BLOBS of values
// - inserts hashes of 32 bytes as indices
func DeletemeCreateNodesBulk3(db DB, count int) error {
	var err error
	c := db.(*mysqlDB)
	_, err = c.db.Exec("LOCK TABLES nodes WRITE;")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("SET autocommit=0")
	if err != nil {
		return err
	}
	// _, err = c.db.Exec("ALTER TABLE `nodes` DISABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("disabling keys: %w", err)
	// }

	blob, err := hex.DecodeString("deadbeef")
	if err != nil {
		panic("logic error")
	}
	// prepare in chunks of 1000 records
	N := 1000
	repeatedStmt := "INSERT INTO nodes (idhash,value) VALUES " + repeatStmt(N, 2)
	// fmt.Printf("Using repeated statement:\n%s\n", repeatedStmt)
	stmt, err := c.db.Prepare(repeatedStmt)
	if err != nil {
		panic("logic error: " + err.Error())
	}

	sequentialHash := (&big.Int{}).Add(&initialSequentialHash, big.NewInt(0))
	bigOne := big.NewInt(1)

	execPreparedStmt := func() error {
		// create the N records slice
		data := make([]interface{}, 2*N) // 2 elements per record ()
		for j := 0; j < N; j++ {
			// ID hash
			idhash := [32]byte{}
			// _, err = rand.Read(idhash[:])

			sequentialHash.Add(sequentialHash, bigOne)
			sequentialHash.FillBytes(idhash[:])
			// sequentialHash.Bits()

			data[2*j] = idhash[:]
			data[2*j+1] = blob
			// fmt.Printf("%s\n", hex.EncodeToString(idhash[:]))
		}
		_, err = stmt.Exec(data...)
		return err
	}

	for i := 0; i < count/N; i++ {
		err = execPreparedStmt()
		if err != nil {
			return err
		}
		if i%100 == 0 {
			fmt.Printf("%d/%d\n", i*N, N*count/N)
		}
	}

	// _, err = c.db.Exec("ALTER TABLE `nodes` ENABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("enabling keys: %w", err)
	// }
	_, err = c.db.Exec("COMMIT")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("UNLOCK TABLES")
	if err != nil {
		return err
	}
	return nil
}

// - inserts BLOBS of values
// - inserts hashes of 32 bytes as indices, random value
func DeletemeCreateNodesBulk4(db DB, count int) error {
	var err error
	c := db.(*mysqlDB)
	_, err = c.db.Exec("LOCK TABLES nodes WRITE;")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("SET autocommit=0")
	if err != nil {
		return err
	}
	// _, err = c.db.Exec("ALTER TABLE `nodes` DISABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("disabling keys: %w", err)
	// }

	blob, err := hex.DecodeString("deadbeef")
	if err != nil {
		panic("logic error")
	}
	// prepare in chunks of 1000 records
	N := 1000
	repeatedStmt := "INSERT INTO nodes (idhash,value) VALUES " + repeatStmt(N, 2)
	// fmt.Printf("Using repeated statement:\n%s\n", repeatedStmt)
	stmt, err := c.db.Prepare(repeatedStmt)
	if err != nil {
		panic("logic error: " + err.Error())
	}

	execPreparedStmt := func() error {
		// create the N records slice
		data := make([]interface{}, 2*N) // 2 elements per record ()
		for j := 0; j < N; j++ {
			// ID hash
			idhash := [32]byte{}
			_, err = rand.Read(idhash[:])

			data[2*j] = idhash[:]
			data[2*j+1] = blob
			// fmt.Printf("%s\n", hex.EncodeToString(idhash[:]))
		}
		_, err = stmt.Exec(data...)
		return err
	}

	for i := 0; i < count/N; i++ {
		err = execPreparedStmt()
		if err != nil {
			return err
		}
		if i%100 == 0 {
			fmt.Printf("%d/%d\n", i*N, N*count/N)
		}
	}

	// _, err = c.db.Exec("ALTER TABLE `nodes` ENABLE KEYS")
	// if err != nil {
	// 	return fmt.Errorf("enabling keys: %w", err)
	// }
	_, err = c.db.Exec("COMMIT")
	if err != nil {
		return err
	}
	_, err = c.db.Exec("UNLOCK TABLES")
	if err != nil {
		return err
	}
	return nil
}

func DeletemeSelectNodes(db DB, count int) error {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()
	c := db.(*mysqlDB)

	initial, err := hex.DecodeString("000000000000010000000000000000000000000000000000000000000004A769")
	if err != nil {
		panic(err)
	}
	if len(initial) != 32 {
		panic("logic error")
	}
	sequentialHash := big.NewInt(0)
	sequentialHash.SetBytes(initial[:])

	for i := 0; i < count; i++ {
		idhash := [32]byte{}
		sequentialHash.FillBytes(idhash[:])
		sequentialHash.Add(sequentialHash, big.NewInt(1))
		row := c.db.QueryRowContext(ctx, "SELECT idhash,value FROM nodes WHERE idhash=?", idhash[:])
		// fmt.Printf("id = %s\n", hex.EncodeToString(idhash[:]))
		retIdHash := []byte{}
		var value []byte
		if err := row.Scan(&retIdHash, &value); err != nil {
			return err
		}
		if i%10000 == 0 {
			fmt.Printf("%d / %d\n", i, count)
		}
	}
	return nil
}

// with prepared stmts
func DeletemeSelectNodes2(db DB, count int) error {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()
	c := db.(*mysqlDB)

	initial, err := hex.DecodeString("000000000000010000000000000000000000000000000000000000000004A769")
	if err != nil {
		panic(err)
	}
	if len(initial) != 32 {
		panic("logic error")
	}
	sequentialHash := big.NewInt(0)
	sequentialHash.SetBytes(initial[:])
	prepStmt, err := c.db.Prepare("SELECT idhash,value FROM nodes WHERE idhash=?")
	if err != nil {
		return err
	}
	for i := 0; i < count; i++ {
		idhash := [32]byte{}
		sequentialHash.FillBytes(idhash[:])
		sequentialHash.Add(sequentialHash, big.NewInt(1))
		row := prepStmt.QueryRowContext(ctx, idhash[:])
		// fmt.Printf("id = %s\n", hex.EncodeToString(idhash[:]))
		retIdHash := []byte{}
		var value []byte
		if err := row.Scan(&retIdHash, &value); err != nil {
			return err
		}
		if i%10000 == 0 {
			fmt.Printf("%d / %d\n", i, count)
		}
	}
	return nil
}

// DeletemeSelectNodes3 has multiple go routines
func DeletemeSelectNodes3(db DB, count int, goroutinesCount int) error {
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()
	c := db.(*mysqlDB)

	initial, err := hex.DecodeString("000000000000010000000000000000000000000000000000000000000004A769")
	if err != nil {
		panic(err)
	}
	if len(initial) != 32 {
		panic("logic error")
	}
	sequentialHash := big.NewInt(0)
	sequentialHash.SetBytes(initial[:])
	prepStmt, err := c.db.Prepare("SELECT idhash,value FROM nodes WHERE idhash=?")
	if err != nil {
		return err
	}

	// to simplify code, check that we run all queries: count must be divisible by routine count
	if count%goroutinesCount != 0 {
		panic("logic error")
	}

	wg := sync.WaitGroup{}
	wg.Add(goroutinesCount)
	for r := 0; r < goroutinesCount; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < count/goroutinesCount; i++ {
				idhash := [32]byte{}
				sequentialHash.FillBytes(idhash[:])
				sequentialHash.Add(sequentialHash, big.NewInt(1))
				row := prepStmt.QueryRowContext(ctx, idhash[:])
				// fmt.Printf("id = %s\n", hex.EncodeToString(idhash[:]))
				retIdHash := []byte{}
				var value []byte
				if err := row.Scan(&retIdHash, &value); err != nil {
					panic(err)
				}
				if i%10000 == 0 {
					fmt.Printf("%d / %d\n", i, count)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

// DeletemeSelectNodes3 has multiple go routines
func DeletemeSelectNodesRandom4(db DB, count int, goroutinesCount int) error {
	c := db.(*mysqlDB)
	ctx, cancelF := context.WithTimeout(context.Background(), time.Minute)
	defer cancelF()

	// taken from the DB:
	randomIDsAsStrings := []string{
		"00000240D1018BF59FB7972978E51B51F2C1128F1E64346134B14B9DA2A2F3EF",
		"00000E0E106675ED2859D10EE5B4CF1AA0BFB86F69A2C71677F806773D46CB0D",
		"00002E2059603154415C2677EC3F94D34452CC19C69856BDBD0618548951CD24",
		"000045C511227476606A079CE4D180A1F3D90F23BAEB2683AF58A3F250E45295",
		"00004F14A66156BA149044C7899E8A46EF40683F9275839134ECDB0E770B5549",
		"0000684BEEBEB84BA6E52B7EB43D985E5781B2D0907A1CBBD9AA821CBDCEDEDA",
		"00008C8C21A9AC1FD43BE574B4C5266B483B895B5380F404A98454A41F1D1B40",
		"0000AAC973337DA5C08F8F0BD425D80E1CD1BE9639D31775C59B67C0993B75BD",
		"0000B43529ADB4EE52E93767118B919CC3E0A746167476A3BCDA1E70694B3793",
		"0000C1FF3319D3A100E99AEDC72FE4A06DCA155B18F32D6B165DCE5B2945626B",
		"0000EF7CAA9B492ED98A76423618416424178144DBDCC183611B6183ACA98BB0",
		"0000F309966C250EC06D5E59DEADA462407C00DEC03FDE834AE0B7D2557E6B6D",
		"0000F66B61ADE5685E8C911B6984867B7AD38C283D112F4E837CF0B5E0E3E5BF",
		"0000F8A095DDF7135B1A9B0F6F4B79C630D025FCBAE648ECF4AAC5F400306B2A",
		"00011DE3E096D8936DF7D97A1D68E69BDE3C5FF11400A6AFC64DC64C1752A201",
		"00012C527D96DB78922C490936AA84681EDFA2146ABFD18E203A16BE821CA664",
		"00013972DB880C7F92DE2BF4DD14FCD69217DAFF6370A7A27695A2B0E1B20AB4",
		"000161DB76A61AF2939B06FE59291DD0AE95E9920FC6E397183FFB66AA8B261E",
		"00016F7C4C089C36A33F1B2658840171936434E879DFBD0801553697659ECD5F",
		"000175B452204838F58B1DD45EC499E1E043FA42099081C510CFA28AAE85E6ED",
		"000180F8B8E55B9886093BC2742A0502CD8614B6C20EAA6071B914C63DEDA5A5",
		"0001A81F372452BC70F17E32F91812FBE15F6809F94095EBFA74F066E6E79766",
		"0001A96BD9EEC86C46213FB3CAA484F11F2AB57A6D84D686CF8C3D2B2B100723",
		"0001AE30E852B98CF4EA47A50245D9BF31784398B4DD6809FF7216F0A55653C6",
		"0001B30FB58F9398C5A9E7E8F3EACD2D24981696D4A92D8551CE59CA20D6E33E",
		"0001B94D063E701A1821C5FCED3B15166AEE77BDBF501EDE5CE2CAE3551B04F2",
		"0001C8A52374253F3D017CAD46300A5FF7941514DCF12E91EA21AE188B0173F1",
		"0001CD7E00EE6A3224368CFE7CD44BA0C42B51FFD80070FDF8E1B1C577CE197E",
		"0001CF09C4771E5D2852649B617465C35D33060AC6F44E89285B8CFC4235F395",
		"0001D33F0AEB9ED1BE7F327DB1EF3707B6F6AF762C84CB385172DCE7C19A58F3",
		"0001E0108BCF6FCA1657B29E18B924C34C66F85C40CE0BDE5732DEB904B0ADE3",
		"00022A901F225FCA0EF3CB4957345A900B77076FAC7B7CC29668AD41BA9C9373",
		"000250193EB08ADA2D967E4A24FC9E0699CB85820FD60CD62C442C4B33E747C3",
		"00025DB69DA1D4CE18F21C482DC51A91AAA6A36FEEA2DAAD155E7878E2CD02D8",
		"00026693EB8C0B0794E1EFD16A388CFA895A885F202B711CAA398E30134FCB59",
		"000283F8FE0B053304AA76CBBA9DF6400D1B26DDCD8868EB053A963D10DA2F3F",
		"000293A43A36A520F32E2729D4921B5B544D3D654E66537166A664333C693BAF",
		"00029A547BCAB67DF0931104705F8293505CECA49517CFE8B0E355B0375C8235",
		"0002B09254BBD9865B0CDF6294D13FAFB772B320CBF78007673FEECB5B905AFD",
		"0002BDBA7ABF200971D023A1036666E2F48C9BB5DDED7096305EA10C2C52EF9B",
		"0002BEB52E40DEB561CC1275BF07CF3A35CB108ECCCF51B9C956A82EA1463D65",
		"0002C2F1C9DFDF7797A33E64702A4B1ADA38BB1064BA1CDAE38C114BB166A9FC",
		"0002C9EDDAA5E67D0A061B66621CAA099049A09F8226D3BFEBD80B7FB50C02D7",
		"0002DBE72E24AC7F47E9E835AF044545DF1F15FE172D6998A5232D637E3EBE5B",
		"0002E98BF8710E356803697A46802938F5CE5D23F83986282982BF509EDD77D4",
		"0002F219DD0E5C4CBBE539192BB8CC08BC7BA48956852471DDFEFD57264DCCB8",
		"0002F39698BE32198553835A3637F81A106A7D0836E9570DB10A83346DB718CD",
		"0002F930CA2FE0633A44EE101A3E2C547DC24C6892646B92318BD66CEB58056E",
		"000300CD064DDC449C1564DCF782B66DB2766F0D78FA70E9E3DC210A5BE90783",
		"000310D9929D999DB3AD5A3AC84089C0EAEAD24EF3CDABDEFB46B50CA507954C",
		"00031CF4200DB5C2BC9EFF80C8703A12BB1C932A2481B58CD85EE8B0BB6EC740",
		"000325AD7EA94E4CF8D560D5014D9DE87E6C7780298C4B424CEB84AD3D96E9B3",
		"00032B81A462C3BFE2A7D3D3AE3F0548115999D910684551AFB86C60999304C7",
		"00032BC35951FD89DB9B28A98991C22118388630B967D664EA12498539C3B053",
		"00032E15D22543F079A60D8451963C4C3B23F071F62B1C6BEF509AF6F1EE30AB",
		"000335E9145652EE37170B8921666F4460B3B7B21DB99A64F72D49E2793EF61D",
		"00033DD55A8453B3CF5EECD904B2886B2EC9E09C4B8387CC2EBCE0C81C40C6F9",
		"00033E4A5965185F0A5C13CE50D4E9AB28A0FD2BD4D2CB3B64B8A3418878AC63",
		"000345F713B222C84E152B7CB11E04FA2E6C1701CF0CAE83755BC53515AEFBEF",
		"0003683192F5BBBE8171F9FB206A99E0118611F79F4E2BFC4085328FB09AB713",
		"000376CD974011D867927E57E9DD8FAA905E85D288F29A8E64AE379DADC4EFCB",
		"000377CBD3BE6FF75D2B5D6A41F49ACBE121FD933B0C2CF48533486B9153C680",
		"000393EBE5343FE35EFFDE7C9910FE85866686C94ACE6CBA9EA9AEF92475C167",
		"0003991C5D4DB32605891386803EE47B9D2A2D13DC61D19052FBB9AC4845ABD1",
	}
	randomIDs := make([][32]byte, len(randomIDsAsStrings))
	for i, s := range randomIDsAsStrings {
		b, err := hex.DecodeString(s)
		if err != nil {
			panic(err)
		}
		if len(b) != 32 {
			panic("logic error")
		}
		copy(randomIDs[i][:], b)
	}

	prepStmt, err := c.db.Prepare("SELECT idhash,value FROM nodes WHERE idhash=?")
	if err != nil {
		return err
	}

	// to simplify code, check that we run all queries: count must be divisible by routine count
	if count%goroutinesCount != 0 {
		panic("logic error: count not divisible by number of routines")
	}

	wg := sync.WaitGroup{}
	wg.Add(goroutinesCount)
	for r := 0; r < goroutinesCount; r++ {
		go func() {
			defer wg.Done()
			for i := 0; i < count/goroutinesCount; i++ {
				idhash := randomIDs[rand.Intn(len(randomIDs))]
				row := prepStmt.QueryRowContext(ctx, idhash[:])
				// fmt.Printf("id = %s\n", hex.EncodeToString(idhash[:]))
				retIdHash := []byte{}
				var value []byte
				if err := row.Scan(&retIdHash, &value); err != nil {
					panic(err)
				}
				if i%10000 == 0 {
					fmt.Printf("%d / %d\n", i, count)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

func repeatStmt(N int, noOfComponents int) string {
	components := make([]string, noOfComponents)
	for i := 0; i < len(components); i++ {
		components[i] = "?"
	}
	toRepeat := "(" + strings.Join(components, ",") + ")"
	return strings.Repeat(toRepeat+",", N-1) + toRepeat
}
