#!/usr/bin/env python3
"""
Kapsamlı Güvenlik Modülü Test Suite
====================================

Tüm security modülünü test eden kapsamlı test script'i.

Author: ozturu68
Date: 2025-11-01
"""

import sys
import time
import traceback
from typing import List, Callable


# =============================================================================
# TEST FRAMEWORK
# =============================================================================

class TestResult:
    """Test sonucu."""
    def __init__(self, name: str, passed: bool, error: str = ""):
        self.name = name
        self.passed = passed
        self.error = error
        self.duration = 0.0


class TestRunner:
    """Test runner."""
    
    def __init__(self):
        self.results: List[TestResult] = []
    
    def run_test(self, name: str, func: Callable) -> bool:
        """Tek bir test çalıştır."""
        print(f"  {name}...", end=" ", flush=True)
        
        start = time.time()
        try:
            func()
            duration = time.time() - start
            print(f"✅ ({duration:.2f}s)")
            
            result = TestResult(name, True)
            result.duration = duration
            self.results.append(result)
            return True
            
        except AssertionError as e:
            duration = time.time() - start
            print(f"❌ ASSERTION ({duration:.2f}s)")
            print(f"     {str(e)}")
            
            result = TestResult(name, False, str(e))
            result.duration = duration
            self.results.append(result)
            return False
            
        except Exception as e:
            duration = time.time() - start
            print(f"❌ EXCEPTION ({duration:.2f}s)")
            print(f"     {str(e)}")
            
            result = TestResult(name, False, str(e))
            result.duration = duration
            self.results.append(result)
            return False
    
    def print_summary(self):
        """Test özeti yazdır."""
        print("\n" + "=" * 80)
        print("TEST ÖZETİ")
        print("=" * 80)
        
        passed = sum(1 for r in self.results if r.passed)
        failed = sum(1 for r in self.results if not r.passed)
        total = len(self.results)
        total_time = sum(r.duration for r in self.results)
        
        print(f"\nToplam Test: {total}")
        print(f"✅ Başarılı: {passed} ({passed/total*100:.1f}%)")
        print(f"❌ Başarısız: {failed} ({failed/total*100:.1f}%)")
        print(f"⏱️  Toplam Süre: {total_time:.2f} saniye")
        
        if failed > 0:
            print("\n🔴 BAŞARISIZ TESTLER:")
            for result in self.results:
                if not result.passed:
                    print(f"  • {result.name}")
                    if result.error:
                        print(f"    Hata: {result.error[:100]}")
        else:
            print("\n🎉 TÜM TESTLER BAŞARILI!")
        
        print("=" * 80)
        
        return failed == 0


# =============================================================================
# TEST SUITE
# =============================================================================

runner = TestRunner()


# =============================================================================
# 1. IMPORT TESTLERİ
# =============================================================================

def test_category_1():
    """Kategori 1: Import Testleri"""
    print("\n" + "=" * 80)
    print("KATEGORİ 1: IMPORT TESTLERİ")
    print("=" * 80)
    
    def test_main_module():
        from src.linux_teknikeri.checks import security
        assert security is not None
    
    def test_dataclasses():
        from src.linux_teknikeri.checks.security import SecuritySummary, PortInfo, SSHAudit
        assert SecuritySummary is not None
    
    def test_enums():
        from src.linux_teknikeri.checks.security import SecurityLevel, SSHSecurityLevel
        assert SecurityLevel is not None
    
    def test_functions():
        from src.linux_teknikeri.checks.security import (
            get_security_summary,
            get_listening_ports,
            audit_ssh_config,
            check_failed_login_attempts
        )
        assert callable(get_security_summary)
    
    def test_backward_compat():
        from src.linux_teknikeri.checks.check_security import get_security_summary
        assert callable(get_security_summary)
    
    def test_ssh_module():
        from src.linux_teknikeri.checks.security.ssh import SSH_CONFIG_RULES
        assert len(SSH_CONFIG_RULES) == 8
    
    runner.run_test("1.1 Ana modül import", test_main_module)
    runner.run_test("1.2 Dataclass import", test_dataclasses)
    runner.run_test("1.3 Enum import", test_enums)
    runner.run_test("1.4 Fonksiyon import", test_functions)
    runner.run_test("1.5 Geriye uyumluluk", test_backward_compat)
    runner.run_test("1.6 SSH modülü", test_ssh_module)


# =============================================================================
# 2. DATACLASS TESTLERİ
# =============================================================================

def test_category_2():
    """Kategori 2: Dataclass Testleri"""
    print("\n" + "=" * 80)
    print("KATEGORİ 2: DATACLASS TESTLERİ")
    print("=" * 80)
    
    from src.linux_teknikeri.checks.security import SecuritySummary, PortInfo, SSHAudit
    
    def test_summary_create():
        s = SecuritySummary(
            security_updates_count=5,
            firewall_status="Aktif",
            apparmor_status="Aktif",
            selinux_status="Kurulu Değil",
            unattended_upgrades="Aktif",
            last_update_check="Bugün"
        )
        assert s.security_updates_count == 5
    
    def test_summary_methods():
        s = SecuritySummary(
            security_updates_count=5,
            firewall_status="Aktif",
            apparmor_status="Aktif",
            selinux_status="Kurulu Değil",
            unattended_upgrades="Aktif",
            last_update_check="Bugün"
        )
        assert 0 <= s.get_security_score() <= 100
        assert s.get_security_level() is not None
    
    def test_port_create():
        p = PortInfo(protocol="tcp", address="0.0.0.0", port="80", process="nginx")
        assert p.is_privileged == True
    
    def test_port_methods():
        p = PortInfo(protocol="tcp", address="0.0.0.0", port="80", process="nginx")
        assert p.is_public() == True
        assert p.get_security_risk() in ["LOW", "MEDIUM", "HIGH"]
    
    def test_ssh_create():
        a = SSHAudit(config_exists=True, port="22")
        assert a.risk_level in ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
    
    def test_ssh_risk():
        a1 = SSHAudit(config_exists=True, port="22", root_login_permitted=True, password_auth_enabled=True)
        assert a1.risk_level == "HIGH"
        
        a2 = SSHAudit(config_exists=True, port="22", empty_passwords_permitted=True)
        assert a2.risk_level == "CRITICAL"
    
    runner.run_test("2.1 SecuritySummary oluşturma", test_summary_create)
    runner.run_test("2.2 SecuritySummary metodlar", test_summary_methods)
    runner.run_test("2.3 PortInfo oluşturma", test_port_create)
    runner.run_test("2.4 PortInfo metodlar", test_port_methods)
    runner.run_test("2.5 SSHAudit oluşturma", test_ssh_create)
    runner.run_test("2.6 SSHAudit risk hesaplama", test_ssh_risk)


# =============================================================================
# 3. ENUM TESTLERİ
# =============================================================================

def test_category_3():
    """Kategori 3: Enum Testleri"""
    print("\n" + "=" * 80)
    print("KATEGORİ 3: ENUM TESTLERİ")
    print("=" * 80)
    
    from src.linux_teknikeri.checks.security import SecurityLevel, SSHSecurityLevel
    
    def test_security_level():
        assert SecurityLevel.EXCELLENT.value == "EXCELLENT"
        assert SecurityLevel.from_score(95) == SecurityLevel.EXCELLENT
    
    def test_security_methods():
        assert SecurityLevel.CRITICAL.needs_immediate_action() == True
        assert SecurityLevel.EXCELLENT.needs_immediate_action() == False
    
    def test_ssh_level():
        assert SSHSecurityLevel.HIGH.value == "HIGH"
        assert SSHSecurityLevel.HIGH.get_priority() == 2
    
    runner.run_test("3.1 SecurityLevel değerler", test_security_level)
    runner.run_test("3.2 SecurityLevel metodlar", test_security_methods)
    runner.run_test("3.3 SSHSecurityLevel", test_ssh_level)


# =============================================================================
# 4. SSH MODÜLÜ TESTLERİ
# =============================================================================

def test_category_4():
    """Kategori 4: SSH Modülü"""
    print("\n" + "=" * 80)
    print("KATEGORİ 4: SSH MODÜLÜ TESTLERİ")
    print("=" * 80)
    
    from src.linux_teknikeri.checks.security.ssh import SSH_CONFIG_RULES, SSHConfigRule
    from src.linux_teknikeri.checks.security.ssh.validators import _validate_root_login
    from src.linux_teknikeri.checks.security import SSHAudit
    
    def test_rules():
        assert len(SSH_CONFIG_RULES) == 8
        assert all(isinstance(r, SSHConfigRule) for r in SSH_CONFIG_RULES)
    
    def test_validators():
        audit = SSHAudit(config_exists=True, port="22")
        msg = _validate_root_login(True, audit)
        assert msg is not None
    
    runner.run_test("4.1 SSH kurallar", test_rules)
    runner.run_test("4.2 Validators", test_validators)


# =============================================================================
# 5. ANA FONKSİYON TESTLERİ (GERÇEK VERİ)
# =============================================================================

def test_category_5():
    """Kategori 5: Gerçek Veri Testleri"""
    print("\n" + "=" * 80)
    print("KATEGORİ 5: ANA FONKSİYON TESTLERİ (GERÇEK VERİ)")
    print("=" * 80)
    print("⚠️  Sudo yetkisi gerekebilir!")
    print()
    
    from src.linux_teknikeri.checks.security import (
        get_security_summary,
        get_listening_ports,
        audit_ssh_config,
        check_failed_login_attempts
    )
    
    def test_summary():
        r = get_security_summary()
        assert isinstance(r, dict)
        assert 'security_updates_count' in r
        print(f"\n     └─ {r['security_updates_count']} güvenlik güncellemesi")
    
    def test_ports():
        r = get_listening_ports()
        assert isinstance(r, list)
        print(f"\n     └─ {len(r)} açık port")
    
    def test_ssh():
        r = audit_ssh_config()
        assert isinstance(r, dict)
        print(f"\n     └─ SSH Risk: {r['risk_level']}")
    
    def test_logins():
        r = check_failed_login_attempts(days=1)
        assert isinstance(r, dict)
        print(f"\n     └─ {r['total_failed']} başarısız giriş")
    
    runner.run_test("5.1 get_security_summary() [GERÇEK]", test_summary)
    runner.run_test("5.2 get_listening_ports() [GERÇEK]", test_ports)
    runner.run_test("5.3 audit_ssh_config() [GERÇEK]", test_ssh)
    runner.run_test("5.4 check_failed_login_attempts() [GERÇEK]", test_logins)


# =============================================================================
# 6. ENTEGRASYON
# =============================================================================

def test_category_6():
    """Kategori 6: Entegrasyon"""
    print("\n" + "=" * 80)
    print("KATEGORİ 6: ENTEGRASYON TESTİ")
    print("=" * 80)
    
    from src.linux_teknikeri.checks.security import get_full_security_report
    
    def test_full_report():
        print("\n     🔄 Tam rapor oluşturuluyor...")
        r = get_full_security_report()
        assert isinstance(r, dict)
        assert 'overall_score' in r
        print(f"\n     └─ Genel Skor: {r['overall_score']}/100")
    
    runner.run_test("6.1 Tam Güvenlik Raporu [ENTEGRASYON]", test_full_report)


# =============================================================================
# ANA
# =============================================================================

def main():
    """Ana test fonksiyonu."""
    print("=" * 80)
    print("KAPSAMLI GÜVENLİK MODÜLÜ TEST SÜİTİ")
    print("=" * 80)
    print()
    
    start = time.time()
    
    test_category_1()  # Import
    test_category_2()  # Dataclass
    test_category_3()  # Enum
    test_category_4()  # SSH
    test_category_5()  # Ana fonksiyonlar
    test_category_6()  # Entegrasyon
    
    total_time = time.time() - start
    print(f"\n⏱️  Toplam test süresi: {total_time:.2f} saniye")
    
    success = runner.print_summary()
    
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
