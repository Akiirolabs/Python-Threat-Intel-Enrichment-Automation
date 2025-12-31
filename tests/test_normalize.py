from soc_automation.normalize import normalize_domain, is_valid_domain, is_valid_ip, is_valid_hash


def test_normalize_domain_defanged():
    assert normalize_domain("Example[.]COM") == "example.com"


def test_valid_domain():
    assert is_valid_domain("telemetry-sync[.]net") is True


def test_valid_ip():
    assert is_valid_ip("8.8.8.8") is True


def test_valid_hash_md5():
    assert is_valid_hash("44d88612fea8a8f36de82e1278abb02f") is True

