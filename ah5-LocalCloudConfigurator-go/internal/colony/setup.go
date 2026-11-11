package colony

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/colonyos/colonies/pkg/client"
	"github.com/colonyos/colonies/pkg/core"
	"github.com/colonyos/colonies/pkg/security/crypto"
)

// Executor types registered by setup.
const APIExecutorType = "lcc-api"

// GenerateSecrets creates the key material of a fresh ColonyOS stack: server, colony, API and cloud executor keys,
// the database password and the operator API token. The values are written to the stack's secret files, never
// printed.
func GenerateSecrets() (map[string]string, error) {
	cr := crypto.CreateCrypto()
	out := map[string]string{}
	for _, k := range []string{"COLONIES_SERVER_PRVKEY", "COLONIES_COLONY_PRVKEY", "LCC_API_PRVKEY", "LCC_EXECUTOR_PRVKEY"} {
		prv, err := cr.GeneratePrivateKey()
		if err != nil {
			return nil, err
		}
		out[k] = prv
	}
	id, err := cr.GenerateID(out["COLONIES_SERVER_PRVKEY"])
	if err != nil {
		return nil, err
	}
	out["COLONIES_SERVER_ID"] = id
	for _, k := range []string{"COLONIES_DB_PASSWORD", "LCC_API_TOKEN"} {
		b := make([]byte, 24)
		if _, err := rand.Read(b); err != nil {
			return nil, err
		}
		out[k] = hex.EncodeToString(b)
	}
	return out, nil
}

// Registration describes the colony and the executors the configurator needs.
type Registration struct {
	Host, ColonyName              string
	Port                          int
	ServerPrvKey, ColonyPrvKey    string
	APIPrvKey, ExecutorPrvKey     string
	ExecutorType, ExecutorName    string
}

// Register creates the colony (if missing) and registers and approves the API and cloud executor identities. It is
// idempotent.
func Register(r Registration) error {
	cr := crypto.CreateCrypto()
	c := client.CreateColoniesClient(r.Host, r.Port, true, false)
	colonyID, err := cr.GenerateID(r.ColonyPrvKey)
	if err != nil {
		return err
	}
	if _, err := c.GetColonyByName(r.ColonyName, r.ServerPrvKey); err != nil {
		if _, err := c.AddColony(core.CreateColony(colonyID, r.ColonyName), r.ServerPrvKey); err != nil {
			return fmt.Errorf("add colony: %w", err)
		}
	}
	for _, e := range []struct{ prv, typ, name string }{
		{r.APIPrvKey, APIExecutorType, "lcc-api"},
		{r.ExecutorPrvKey, r.ExecutorType, r.ExecutorName},
	} {
		id, err := cr.GenerateID(e.prv)
		if err != nil {
			return err
		}
		if existing, err := c.GetExecutor(r.ColonyName, e.name, r.ColonyPrvKey); err == nil && existing != nil {
			if existing.ID == id {
				if existing.State != core.APPROVED {
					if err := c.ApproveExecutor(r.ColonyName, e.name, r.ColonyPrvKey); err != nil {
						return fmt.Errorf("approve %s: %w", e.name, err)
					}
				}
				continue
			}
			if err := c.RemoveExecutor(r.ColonyName, e.name, r.ColonyPrvKey); err != nil {
				return fmt.Errorf("remove stale %s: %w", e.name, err)
			}
		}
		ex := core.CreateExecutor(id, e.typ, e.name, r.ColonyName, time.Now(), time.Now())
		if _, err := c.AddExecutor(ex, r.ColonyPrvKey); err != nil && !strings.Contains(err.Error(), "already") {
			return fmt.Errorf("add executor %s: %w", e.name, err)
		}
		if err := c.ApproveExecutor(r.ColonyName, e.name, r.ColonyPrvKey); err != nil {
			return fmt.Errorf("approve %s: %w", e.name, err)
		}
	}
	return nil
}
