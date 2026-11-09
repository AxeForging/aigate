package actions

import (
	"fmt"
	"os"

	"github.com/AxeForging/aigate/services"
	"github.com/urfave/cli"
)

type WhoamiAction struct {
	configSvc *services.ConfigService
	idSvc     *services.IdentityService
}

func NewWhoamiAction(c *services.ConfigService) *WhoamiAction {
	return &WhoamiAction{configSvc: c, idSvc: services.NewIdentityService()}
}

// Execute prints which identity `aigate run` would use here, and why.
func (a *WhoamiAction) Execute(c *cli.Context) error {
	cfg, err := a.configSvc.LoadGlobal()
	if err != nil {
		return fmt.Errorf("aigate isn't set up yet. Run: aigate init")
	}
	workDir, _ := os.Getwd()
	id, err := a.idSvc.Resolve(cfg, c.String("identity"), workDir)
	if err != nil {
		return err
	}
	switch {
	case id != nil:
		printIdentity(cfg, id)
		fmt.Printf("  why:      %s\n", id.Reason)
		printProblems(a.idSvc.Validate(cfg), id.Name)
	case len(cfg.Identities) == 0:
		fmt.Println("identity: none — no identities configured, so sessions use your normal logins.")
		fmt.Println("  Create one: aigate identity add NAME")
	default:
		fmt.Printf("identity: none — %s isn't bound to an identity and there is no default_identity.\n", tildePath(workDir))
		fmt.Println("  Bind this folder: aigate identity use NAME   (identities: aigate identity list)")
	}
	return nil
}
