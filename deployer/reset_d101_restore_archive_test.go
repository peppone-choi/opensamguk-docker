package main

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
)

func TestRestoreArchiveCommandRequiresActualIdentityArgsAndRootUser(t *testing.T) {
	id := strings.Repeat("a", 64)
	for _, mode := range []string{"valid", "wrong-id", "wrong-path", "wrong-args", "wrong-user", "duplicate", "unknown"} {
		fields := map[string]any{"id": id, "path": "pg_restore", "args": []string{"--list", "/run/d101/backup.dump"}, "user": "0:0"}
		switch mode {
		case "wrong-id":
			fields["id"] = strings.Repeat("b", 64)
		case "wrong-path":
			fields["path"] = "sh"
		case "wrong-args":
			fields["args"] = []string{"--dbname=other", "/run/d101/backup.dump"}
		case "wrong-user":
			fields["user"] = "postgres"
		case "unknown":
			fields["privileged"] = false
		}
		wire, _ := json.Marshal(fields)
		if mode == "duplicate" {
			wire = []byte(strings.Replace(string(wire), `"user":"0:0"`, `"user":"0:0","user":"0:0"`, 1))
		}
		calls := 0
		c := config{dockerRunnerContext: func(_ context.Context, args ...string) (string, error) {
			calls++
			if len(args) != 4 || args[0] != "inspect" || args[1] != "--format" || args[3] != id {
				t.Fatal("unexpected physical command")
			}
			return string(wire), nil
		}}
		err := c.requireResetD101RestoreArchiveCommand(context.Background(), id)
		if (err == nil) != (mode == "valid") || calls != 1 {
			t.Fatal("observed command identity mismatch", mode, err)
		}
	}
}
func TestRestoreArchiveMountsRejectWriteableOrAdditionalVolumes(t *testing.T) {
	host := "/srv/opensamguk/backups/pep/" + strings.Repeat("a", 32) + "/postgres.dump"
	fixture := resetD101CapsJob{Mounts: []resetD101CapsMount{{"bind", host, "/run/d101/backup.dump", false}, {"tmpfs", "", "/var/lib/postgresql/data", true}}}
	if !validResetD101RestoreArchiveMounts(fixture, host) {
		t.Fatal("fixed RO dump mount rejected")
	}
	for _, mode := range []string{"writeable", "other-source", "other-destination", "extra-volume"} {
		job := fixture
		job.Mounts = append([]resetD101CapsMount(nil), fixture.Mounts...)
		switch mode {
		case "writeable":
			job.Mounts[0].RW = true
		case "other-source":
			job.Mounts[0].Source = "/other/postgres.dump"
		case "other-destination":
			job.Mounts[0].Destination = "/var/lib/postgresql/data"
		case "extra-volume":
			job.Mounts = append(job.Mounts, resetD101CapsMount{"volume", "other", "/other", true})
		}
		if validResetD101RestoreArchiveMounts(job, host) {
			t.Fatal("unsafe restore-list mount accepted", mode)
		}
	}
}
func TestRestoreArchiveMissingOriginalBindingCannotInvokeDocker(t *testing.T) {
	calls := 0
	c := config{dockerRunnerContext: func(context.Context, ...string) (string, error) { calls++; return "", nil }}
	observed, err := c.observeResetD101RestoreArchive(context.Background(), resetD101RecoveryBinding{}, func(context.Context) error { return nil })
	if err == nil || calls != 0 || observed.ContainerID != "" || observed.ListOriginalSHA != "" {
		t.Fatal("missing original binding produced archive proof")
	}
}
