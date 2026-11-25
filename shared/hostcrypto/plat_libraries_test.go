package hostcrypto

import (
	"os/exec"
	"strings"
	"testing"

	"github.com/vistasecurity/vistaplatform-agents/shared/hostinventory"
)

func TestPlatParsePackages(t *testing.T) {
	out := "dpkg\topenssl\t3.0.13-0ubuntu3\n" +
		"dpkg\tlibssl3t64\t3.0.13-0ubuntu3\n" +
		"dpkg\tlibssl-dev\t3.0.13-0ubuntu3\n" +
		"dpkg\tlibgnutls30t64\t3.8.3-1\n" +
		"dpkg\tlibnss3\t2:3.98-1\n" +
		"dpkg\tlibgcrypt20\t1.10.3-2\n" +
		"dpkg\tlibmbedtls14t64\t2.28.8-1\n" +
		"dpkg\tlibbcprov-java\t1.77-1\n" +
		"rpm\tnss-pam-ldapd\t0.9-1\n" +
		"rpm\topenssl-libs\t3.2.2-6.el10\n" +
		"rpm\tnss\t3.101-1.el10\n" +
		"rpm\topenssl-fips-provider\t3.0.7-6.el10\n" +
		"apk\tlibcrypto3-3.3.2-r1\n" +
		"apk\twolfssl-5.7.2-r0\n" +
		"apk\tgarbage\n" +
		"dpkg\tbad\tversion with spaces\n"
	libs := platParsePackages([]byte(out))
	got := map[string]string{}
	for _, l := range libs {
		if l.Source != "package" || l.Path != "" {
			t.Fatalf("%+v", l)
		}
		got[l.Package] = l.Name + " " + l.Version
	}
	want := map[string]string{
		"openssl": "openssl 3.0.13-0ubuntu3", "libssl3t64": "openssl 3.0.13-0ubuntu3", "libgnutls30t64": "gnutls 3.8.3-1",
		"libnss3": "nss 2:3.98-1", "libgcrypt20": "libgcrypt 1.10.3-2", "libmbedtls14t64": "mbedtls 2.28.8-1",
		"libbcprov-java": "bouncycastle 1.77-1", "openssl-libs": "openssl 3.2.2-6.el10", "nss": "nss 3.101-1.el10",
		"openssl-fips-provider": "openssl 3.0.7-6.el10", "libcrypto3": "openssl 3.3.2-r1", "wolfssl": "wolfssl 5.7.2-r0",
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s: %q, want %q", k, got[k], v)
		}
	}
	if len(got) != len(want) {
		t.Errorf("extra: %v", got)
	}
	for _, l := range libs {
		if l.Name == "openssl" && (l.FIPSProvider == nil || !*l.FIPSProvider) {
			t.Errorf("a FIPS provider package is installed, %s says otherwise", l.Package)
		}
		if l.Name != "openssl" && l.FIPSProvider != nil {
			t.Errorf("%s: FIPS set", l.Package)
		}
	}
}

func TestPlatParseOpenSSLVersion(t *testing.T) {
	v, ok := platParseOpenSSLVersion([]byte("path /usr/bin/openssl\nOpenSSL 3.0.13 30 Jan 2024 (Library: OpenSSL 3.0.13 30 Jan 2024)\nOPENSSLDIR: \"/usr/lib/ssl\"\nMODULESDIR: \"/usr/lib/ossl-modules\"\n"))
	if !ok || v.name != "openssl" || v.version != "3.0.13" || v.path != "/usr/bin/openssl" || v.modulesDir != "/usr/lib/ossl-modules" || v.fips {
		t.Fatalf("%+v", v)
	}
	v, _ = platParseOpenSSLVersion([]byte("path /usr/bin/openssl\nLibreSSL 3.3.6\n"))
	if v.name != "libressl" || v.version != "3.3.6" {
		t.Fatalf("%+v", v)
	}
	v, _ = platParseOpenSSLVersion([]byte("OpenSSL 1.0.2k-fips  26 Jan 2017\n"))
	if !v.fips || v.version != "1.0.2k-fips" {
		t.Fatalf("%+v", v)
	}
	if _, ok := platParseOpenSSLVersion([]byte("command not found\n")); ok {
		t.Fatal("garbage accepted")
	}
}

func TestPlatLibraryFile(t *testing.T) {
	for p, want := range map[string]string{
		"/usr/lib/x86_64-linux-gnu/libssl.so.3":                "openssl  false",
		"/usr/lib/x86_64-linux-gnu/libcrypto.so.3":             "openssl  false",
		"/usr/lib/ossl-modules/fips.so":                        "openssl  true",
		"/opt/libressl/lib/libcrypto.so.50":                    "libressl  false",
		"/usr/lib/libtls.so.28":                                "libressl  false",
		"/usr/lib/libgnutls.so.30.37.1":                        "gnutls  false",
		"/usr/lib/libnss3.so":                                  "nss  false",
		"/usr/lib/libgcrypt.so.20":                             "libgcrypt  false",
		"/usr/lib/libwolfssl.so.42":                            "wolfssl  false",
		"/usr/lib/libmbedcrypto.so.7":                          "mbedtls  false",
		"/usr/share/java/bcprov-jdk18on-1.78.1.jar":            "bouncycastle 1.78.1 false",
		"/opt/app/lib/bc-fips-2.0.0.jar":                       "bouncycastle 2.0.0 true",
		`C:\Program Files\Git\mingw64\bin\libcrypto-3-x64.dll`: "openssl  false",
		`C:\Windows\System32\schannel.dll`:                     "schannel  false",
		`C:\app\libeay32.dll`:                                  "openssl  false",
		"/usr/lib/libsslwrapper.so":                            "",
		"/usr/lib/libc.so.6":                                   "",
	} {
		name, fips, ver := platLibraryFile(p)
		got := ""
		if name != "" {
			got = name + " " + ver + " " + map[bool]string{true: "true", false: "false"}[fips]
		}
		if got != want {
			t.Errorf("%s: %q, want %q", p, got, want)
		}
	}
	libs := platParseLibFiles([]byte("/usr/lib/libssl.so.3\nrelative/libssl.so.3\n/usr/lib/libc.so.6\n/usr/lib/libssl\x01.so\n"), false)
	if len(libs) != 1 || libs[0].Path != "/usr/lib/libssl.so.3" || libs[0].Source != "file" {
		t.Fatalf("%+v", libs)
	}
}

func TestPlatParseBrew(t *testing.T) {
	out := "/opt/homebrew/opt/openssl@3 ../Cellar/openssl@3/3.4.0\n/opt/homebrew/opt/openssl ../Cellar/openssl@3/3.4.0\n/opt/homebrew/opt/gnutls ../Cellar/gnutls/3.8.4_1\n/opt/homebrew/opt/x ../Cellar/x/1.0\nnonsense\n"
	libs := platParseBrew([]byte(out))
	if len(libs) != 2 || libs[0].Name != "openssl" || libs[0].Version != "3.4.0" || libs[0].Package != "homebrew:openssl@3" || libs[1].Version != "3.8.4_1" {
		t.Fatalf("%+v", libs)
	}
}

func TestPlatParseWindowsLibraries(t *testing.T) {
	ans := platJSON(t, map[string]any{"Truncated": true, "Libs": []map[string]any{
		{"Path": `C:\Windows\system32\schannel.dll`, "Version": "10.0.26100.1 (WinBuild.160101.0800)"},
		{"Path": `C:\Program Files\App\libcrypto-3-x64.dll`, "Version": "3.5.5"},
		{"Path": `C:\Program Files\App\ossl-modules\fips.dll`, "Version": ""},
		{"Path": `relative\libssl.dll`, "Version": "1"},
		{"Path": `C:\Program Files\App\other.dll`, "Version": "1"},
	}})
	libs, trunc, err := platParseWindowsLibraries([]byte(ans))
	if err != nil || !trunc || len(libs) != 3 {
		t.Fatalf("%v %v %+v", err, trunc, libs)
	}
	if libs[0].Name != "schannel" || libs[0].Version != "10.0.26100.1" || libs[2].FIPSProvider == nil {
		t.Fatalf("%+v", libs)
	}
}

func TestPlatLibrariesThroughTargets(t *testing.T) {
	for _, local := range []bool{true, false} {
		ft := newTgtFakeTarget(local)
		ft.script(platSh(platPkgScript), tgtResult{stdout: "dpkg\tlibssl3\t3.0.13-1\n"})
		ft.script(platSh(platOpenSSLScript), tgtResult{stdout: "path /usr/bin/openssl\nOpenSSL 3.0.13 30 Jan 2024\nMODULESDIR: \"/usr/lib/ossl-modules\"\n"})
		ft.file("/usr/lib/ossl-modules/fips.so", []byte("\x7fELF"))
		ft.script(platSh(platLinuxLibFilesScript), tgtResult{stdout: "/usr/lib/libssl.so.3\n"})
		c := tgtCollection(ft, Options{Platform: hostinventory.PlatformLinux})
		platLinuxLibraries(t.Context(), c)
		c.registry.finish(c.report)
		if c.report.Sections[SectionLibraries] != SectionOK || len(c.report.Libraries) != 3 {
			t.Fatalf("local=%v: %v %+v", local, c.report.Sections, c.report.Libraries)
		}
		for _, l := range c.report.Libraries {
			if l.Path == "/usr/bin/openssl" && (l.FIPSProvider == nil || !*l.FIPSProvider) {
				t.Fatalf("the FIPS module was not seen: %+v", l)
			}
		}

		// No package database: said, not failed; the files still count.
		ft = newTgtFakeTarget(local)
		ft.script(platSh(platLinuxLibFilesScript), tgtResult{stdout: "/usr/lib/libssl.so.3\n"})
		c = tgtCollection(ft, Options{Platform: hostinventory.PlatformLinux})
		platLinuxLibraries(t.Context(), c)
		if c.report.Sections[SectionLibraries] != SectionOK || !platErrorsContain(c.report, SectionLibraries, "no package database") {
			t.Fatalf("no packages: %v %+v", c.report.Sections, c.report.Errors)
		}

		// macOS.
		ft = newTgtFakeTarget(local)
		ft.script(platSwVersArgv, tgtResult{stdout: "26.1\n"})
		ft.script(platSh(platOpenSSLScript), tgtResult{stdout: "path /usr/bin/openssl\nLibreSSL 3.3.6\n"})
		ft.script(platSh(platBrewScript), tgtResult{stdout: "/opt/homebrew/opt/openssl@3 ../Cellar/openssl@3/3.4.0\n"})
		c = tgtCollection(ft, Options{Platform: hostinventory.PlatformDarwin})
		platDarwinLibraries(t.Context(), c)
		c.registry.finish(c.report)
		names := []string{}
		for _, l := range c.report.Libraries {
			names = append(names, l.Name+"@"+l.Version)
		}
		if strings.Join(names, ",") != "corecrypto@26.1,libressl@3.3.6,openssl@3.4.0" {
			t.Fatalf("darwin: %v", names)
		}
	}
}

func TestPlatRealLinuxLibraries(t *testing.T) {
	if _, err := exec.LookPath("find"); err != nil {
		t.Skip("no find")
	}
	c := tgtCollection(NewLocalTarget(), Options{Platform: hostinventory.PlatformLinux})
	platLinuxLibraries(t.Context(), c)
	if s := c.report.Sections[SectionLibraries]; s != SectionOK && s != SectionPartial {
		t.Fatalf("%v %+v", c.report.Sections, c.report.Errors)
	}
	for _, e := range c.report.Errors {
		if !strings.Contains(e.Message, "package database") {
			t.Errorf("error: %+v", e)
		}
	}
}
