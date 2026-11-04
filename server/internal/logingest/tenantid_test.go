package logingest

import "testing"

// SourceIDTenant: kiracısız kaynak ve dağıtım kiracısına bağlı kaynak kimliği DEĞİŞTİRMEZ;
// yalnız dağıtım kiracısından farklı açık kiracı ad-alanlanır.
func TestSourceIDTenant(t *testing.T) {
	cases := []struct{ explicit, deploy, want string }{
		{"", "acme", ""},
		{"  ", "acme", ""},
		{"", "", ""},
		{"acme", "acme", ""},
		{"ACME ", "acme", ""},
		{"default", "", ""},
		{"beta", "acme", "beta"},
		{"Beta ", "acme", "beta"},
		{"acme", "", "acme"},
		{"acme", "default", "acme"},
	}
	for _, c := range cases {
		if got := SourceIDTenant(c.explicit, c.deploy); got != c.want {
			t.Errorf("SourceIDTenant(%q,%q)=%q, want %q", c.explicit, c.deploy, got, c.want)
		}
	}
	// Legacy kaynak: kimlik kiracı damgalama öncesiyle bire bir aynı.
	id := SourceUUID("fw1")
	if got := TenantDeviceID(SourceIDTenant("", "acme"), id); got != id {
		t.Fatalf("legacy kimlik değişmemeli: %s != %s", got, id)
	}
}
