package main

import (
	"bytes"
	"context"
	"os"
	"runtime"
	"strings"
	"testing"
)

// These CLI observers do not read a target, create a key or authorize an
// operation. A factory call stands for the point at which those become possible.
type nativeProductionCLIFactoryObserver struct {
	calls     int
	entry     string
	op        string
	installer *resetD101NativeAuthorityInstaller
	before    func()
}

func (f *nativeProductionCLIFactoryObserver) OpenApprovedEntry(_ context.Context, entry, op string) (*resetD101NativeAuthorityInstaller, error) {
	f.calls++
	f.entry, f.op = entry, op
	if f.before != nil {
		f.before()
	}
	if f.installer == nil {
		return nil, errResetD101InstallationNotSupplied
	}
	return f.installer, nil
}

func nativeProductionCLIPreserveState(t *testing.T) *resetD101NativeAuthorityInstaller {
	t.Helper()
	factory, installer := resetD101ReviewedNativeEntryFactory, resetD101ReviewedNativeAuthorityInstaller
	ceremony, ceremonySource := resetD101ReviewedKey3CeremonyExpected, resetD101ReviewedKey3CeremonySource
	execution, executionSource := resetD101ReviewedKey3NativeInitializationExpected, resetD101ReviewedKey3NativeInitializationSource
	t.Cleanup(func() {
		resetD101ReviewedNativeEntryFactory, resetD101ReviewedNativeAuthorityInstaller = factory, installer
		resetD101ReviewedKey3CeremonyExpected, resetD101ReviewedKey3CeremonySource = ceremony, ceremonySource
		resetD101ReviewedKey3NativeInitializationExpected, resetD101ReviewedKey3NativeInitializationSource = execution, executionSource
	})
	marker := &resetD101NativeAuthorityInstaller{}
	resetD101ReviewedNativeAuthorityInstaller = marker
	resetD101ReviewedKey3CeremonyExpected, resetD101ReviewedKey3CeremonySource = nil, nil
	resetD101ReviewedKey3NativeInitializationExpected, resetD101ReviewedKey3NativeInitializationSource = nil, nil
	return marker
}

func nativeProductionCLIAssertNoRegistration(t *testing.T, marker *resetD101NativeAuthorityInstaller, expected *resetD101Key3CeremonyExpected) {
	t.Helper()
	if resetD101ReviewedNativeAuthorityInstaller != marker || resetD101ReviewedKey3CeremonyExpected != expected ||
		resetD101ReviewedKey3CeremonySource != nil || resetD101ReviewedKey3NativeInitializationExpected != nil || resetD101ReviewedKey3NativeInitializationSource != nil {
		t.Fatal("rejected CLI published or replaced installation/key3 registration")
	}
}

func TestNativeProductionCLIRejectsMalformedBeforeFactory(t *testing.T) {
	marker := nativeProductionCLIPreserveState(t)
	op, sha := strings.Repeat("a", 32), strings.Repeat("b", 64)
	type rejection struct {
		name string
		args []string
		env  func(string) string
	}
	cases := []rejection{
		{"key3-missing", []string{"deployer", "--d101-initialize-key3"}, nil},
		{"key3-wrong-flag", []string{"deployer", "--d101-initialize-key3", "--operation-id", sha}, nil},
		{"key3-short-sha", []string{"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", "approved"}, nil},
		{"key3-uppercase-sha", []string{"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", strings.Repeat("B", 64)}, nil},
		{"key3-extra", []string{"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", sha, "extra"}, nil},
		{"relay-extra", []string{"deployer", "--d101-prepared-relay", "extra"}, func(string) string { return "valid-test-transport" }},
		{"relay-no-env", []string{"deployer", "--d101-prepared-relay"}, nil},
		{"relay-empty-token", []string{"deployer", "--d101-prepared-relay"}, func(string) string { return "" }},
		{"relay-space-token", []string{"deployer", "--d101-prepared-relay"}, func(string) string { return "token with space" }},
		{"relay-control-token", []string{"deployer", "--d101-prepared-relay"}, func(string) string { return "token\n" }},
		{"keeper-missing", []string{"deployer", "--d101-native-keeper"}, nil},
		{"keeper-wrong-flag", []string{"deployer", "--d101-native-keeper", "--ceremony-card-sha256", op}, nil},
		{"keeper-wrong-suffix", []string{"deployer", "--d101-native-keeper", "--operation-id", op, "--unknown"}, nil},
	}
	for _, entry := range []string{"--d101-host-operation", "--d101-issue-current-receipt"} {
		cases = append(cases,
			rejection{entry + "-missing", []string{"deployer", entry}, nil},
			rejection{entry + "-wrong-flag", []string{"deployer", entry, "--ceremony-card-sha256", op}, nil},
			rejection{entry + "-uppercase-op", []string{"deployer", entry, "--operation-id", strings.Repeat("A", 32)}, nil},
			rejection{entry + "-short-op", []string{"deployer", entry, "--operation-id", op[:31]}, nil},
			rejection{entry + "-extra", []string{"deployer", entry, "--operation-id", op, "extra"}, nil})
	}
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		cases = append(cases, rejection{"key3-unsupported-platform-or-uid", []string{"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", sha}, nil})
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			factory := &nativeProductionCLIFactoryObserver{}
			resetD101ReviewedNativeEntryFactory = factory
			var out, errOut bytes.Buffer
			handled, status := earlyResetD101HostCommand(c.args, c.env, &out, &errOut)
			if !handled || status != 2 || factory.calls != 0 || out.Len() != 0 || errOut.Len() != 0 {
				t.Fatal("malformed selector reached factory/target-read boundary or changed early denial")
			}
			nativeProductionCLIAssertNoRegistration(t, marker, nil)
		})
	}
}

func TestNativeProductionCLIValidSelectorsPreserveFactoryArguments(t *testing.T) {
	marker := nativeProductionCLIPreserveState(t)
	op := strings.Repeat("a", 32)
	for _, entry := range []string{"--d101-host-operation", "--d101-issue-current-receipt", "--d101-prepared-relay"} {
		t.Run(entry, func(t *testing.T) {
			args, wantOp := []string{"deployer", entry, "--operation-id", op}, op
			if entry == "--d101-prepared-relay" {
				args, wantOp = []string{"deployer", entry}, ""
			}
			factory := &nativeProductionCLIFactoryObserver{}
			resetD101ReviewedNativeEntryFactory = factory
			var out, errOut bytes.Buffer
			handled, status := earlyResetD101HostCommand(args, func(string) string { return "valid-test-transport" }, &out, &errOut)
			if !handled || status != 2 || factory.calls != 1 || factory.entry != entry || factory.op != wantOp || out.Len() != 0 || errOut.Len() != 0 {
				t.Fatal("valid CLI selector changed factory arguments or failed closed behavior")
			}
			nativeProductionCLIAssertNoRegistration(t, marker, nil)
		})
	}
}

func TestNativeProductionCLIOrdinaryPathsNeverOpenFactory(t *testing.T) {
	marker := nativeProductionCLIPreserveState(t)
	for _, args := range [][]string{{}, {"deployer"}, {"deployer", "--check-registry"}, {"deployer", "--unknown"}} {
		factory := &nativeProductionCLIFactoryObserver{}
		resetD101ReviewedNativeEntryFactory = factory
		envCalls := 0
		var out, errOut bytes.Buffer
		handled, status := earlyResetD101HostCommand(args, func(string) string { envCalls++; return "transport" }, &out, &errOut)
		if handled || status != 0 || factory.calls != 0 || envCalls != 0 || out.Len() != 0 || errOut.Len() != 0 {
			t.Fatal("ordinary/unknown command opened native factory or lost fallthrough")
		}
		nativeProductionCLIAssertNoRegistration(t, marker, nil)
	}
}

func TestNativeProductionCLINilFactoryPreservesKey3Denial(t *testing.T) {
	marker := nativeProductionCLIPreserveState(t)
	resetD101ReviewedNativeEntryFactory = nil
	sha := strings.Repeat("a", 64)
	for _, args := range [][]string{{"deployer", "--d101-initialize-key3"}, {"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", sha}} {
		var out, errOut bytes.Buffer
		envCalls := 0
		handled, status := earlyResetD101HostCommand(args, func(string) string { envCalls++; return "transport" }, &out, &errOut)
		if !handled || status != 2 || envCalls != 0 || out.Len() != 0 || errOut.Len() != 0 {
			t.Fatal("nil factory changed existing uninstalled key3 denial or read config")
		}
		nativeProductionCLIAssertNoRegistration(t, marker, nil)
	}
}

func TestNativeProductionKey3IndependentSHARejectsBeforeOpen(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Skip("key3 valid CLI binding requires Linux amd64 UID0; malformed/platform cases are portable")
	}
	marker := nativeProductionCLIPreserveState(t)
	sha := strings.Repeat("a", 64)
	for _, name := range []string{"absent", "empty", "different", "matching"} {
		t.Run(name, func(t *testing.T) {
			var expected *resetD101Key3CeremonyExpected
			if name != "absent" {
				expected = &resetD101Key3CeremonyExpected{}
				if name == "different" {
					expected.CardSHA = strings.Repeat("b", 64)
				} else if name == "matching" {
					expected.CardSHA = sha
				}
			}
			resetD101ReviewedKey3CeremonyExpected = expected
			factory := &nativeProductionCLIFactoryObserver{}
			resetD101ReviewedNativeEntryFactory = factory
			var out, errOut bytes.Buffer
			handled, status := earlyResetD101HostCommand([]string{"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", sha}, nil, &out, &errOut)
			wantCalls := 0
			if name == "matching" {
				wantCalls = 1
			}
			if !handled || status != 2 || factory.calls != wantCalls || out.Len() != 0 || errOut.Len() != 0 || (wantCalls == 1 && (factory.entry != "--d101-initialize-key3" || factory.op != "")) {
				t.Fatal("CLI SHA learned its independent expectation from factory/target or changed valid key3 arguments")
			}
			nativeProductionCLIAssertNoRegistration(t, marker, expected)
		})
	}
}

// This isolated observer allows entry validation and deliberately rejects
// key3 registration. It never grants ceremony, initialization or runtime trust.
type nativeProductionCLIInstallationObserver struct {
	entryCalls, key3Calls int
}

func (s *nativeProductionCLIInstallationObserver) AuthenticateInstallation(_ context.Context, _, entry string) error {
	if entry == "key3" {
		s.key3Calls++
		return errResetD101InstallationNotSupplied
	}
	s.entryCalls++
	return nil
}
func (*nativeProductionCLIInstallationObserver) RecheckInstallation(context.Context, string, string) error {
	return nil
}

type nativeProductionCLICeremonyDenied struct{}

func (*nativeProductionCLICeremonyDenied) Authenticate(context.Context, resetD101Key3CeremonyExpected, resetD101UnverifiedKey3Ceremony) (resetD101Key3CeremonyAuthentication, error) {
	return resetD101Key3CeremonyAuthentication{}, errResetD101InstallationNotSupplied
}
func (*nativeProductionCLICeremonyDenied) Recheck(context.Context, resetD101Key3CeremonyExpected, resetD101Key3CeremonyAuthentication) error {
	return errResetD101InstallationNotSupplied
}

type nativeProductionCLIExecutionDenied struct{}

func (*nativeProductionCLIExecutionDenied) Authenticate(context.Context, *resetD101Key3AuthenticatedSession, resetD101Key3NativeInitializationExpected) (resetD101Key3NativeInitializationBinding, error) {
	return resetD101Key3NativeInitializationBinding{}, errResetD101InstallationNotSupplied
}
func (*nativeProductionCLIExecutionDenied) Recheck(context.Context, *resetD101Key3AuthenticatedSession, resetD101Key3NativeInitializationExpected, resetD101Key3NativeInitializationBinding) error {
	return errResetD101InstallationNotSupplied
}

func TestNativeProductionKey3ReturnedBundleRecheckedBeforeRegistration(t *testing.T) {
	if runtime.GOOS != "linux" || runtime.GOARCH != "amd64" || os.Geteuid() != 0 {
		t.Skip("key3 returned bundle binding requires Linux amd64 UID0")
	}
	marker := nativeProductionCLIPreserveState(t)
	sha := strings.Repeat("a", 64)
	for _, name := range []string{"absent-key3", "absent-ceremony", "different-bundle", "replaced-expectation", "changed-expectation", "matching-bundle"} {
		t.Run(name, func(t *testing.T) {
			expected := &resetD101Key3CeremonyExpected{CardSHA: sha}
			wantExpected := expected
			resetD101ReviewedKey3CeremonyExpected = expected
			installation := &nativeProductionCLIInstallationObserver{}
			bundle := &resetD101NativeKey3Inputs{
				ceremony:        &resetD101Key3CeremonyExpected{CardSHA: sha},
				ceremonySource:  &nativeProductionCLICeremonyDenied{},
				execution:       &resetD101Key3NativeInitializationExpected{},
				executionSource: &nativeProductionCLIExecutionDenied{},
			}
			factory := &nativeProductionCLIFactoryObserver{installer: &resetD101NativeAuthorityInstaller{installation: installation, key3: bundle}}
			switch name {
			case "absent-key3":
				factory.installer.key3 = nil
			case "absent-ceremony":
				bundle.ceremony = nil
			case "different-bundle":
				bundle.ceremony.CardSHA = strings.Repeat("b", 64)
			case "replaced-expectation":
				wantExpected = &resetD101Key3CeremonyExpected{CardSHA: sha}
				factory.before = func() { resetD101ReviewedKey3CeremonyExpected = wantExpected }
			case "changed-expectation":
				factory.before = func() { expected.CardSHA = strings.Repeat("b", 64) }
			}
			resetD101ReviewedNativeEntryFactory = factory
			var out, errOut bytes.Buffer
			handled, status := earlyResetD101HostCommand([]string{"deployer", "--d101-initialize-key3", "--ceremony-card-sha256", sha}, nil, &out, &errOut)
			wantRegistrationCalls := 0
			if name == "matching-bundle" {
				wantRegistrationCalls = 1
			}
			if !handled || status != 2 || factory.calls != 1 || installation.entryCalls != 1 || installation.key3Calls != wantRegistrationCalls || out.Len() != 0 || errOut.Len() != 0 {
				t.Fatal("changed/absent returned bundle reached key3 registration or matching denied registration changed status")
			}
			nativeProductionCLIAssertNoRegistration(t, marker, wantExpected)
		})
	}
}
