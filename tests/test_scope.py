from hunter_agent.scope import ScopeGuard, OutOfScopeError


def test_scope_allows_subdomain():
    guard = ScopeGuard("https://example.com")
    assert guard.is_allowed("https://api.example.com/x")


def test_scope_rejects_suffix_attack():
    guard = ScopeGuard("https://example.com")
    assert not guard.is_allowed("https://example.com.evil.test/x")


def test_scope_enforce():
    guard = ScopeGuard("https://example.com")
    try:
        guard.enforce("https://evil.test")
        assert False
    except OutOfScopeError:
        assert True
