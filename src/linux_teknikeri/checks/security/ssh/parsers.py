"""
SSH Yapılandırma Parser Fonksiyonları
======================================

SSH config dosyasını okuma, parse etme ve işleme fonksiyonları.

Bu modül SSH config dosyasını okur, parse eder ve kuralları uygular.
Low-level işlemler burada yapılır.

Fonksiyonlar:
    _read_ssh_config()     - SSH config dosyasını okur
    _parse_ssh_setting()   - Tek bir ayarı parse eder
    _apply_ssh_rules()     - Tüm kuralları uygular
    _parse_yes_no()        - yes/no değerlerini parse eder (helper)
    _normalize_config()    - Config içeriğini normalize eder (helper)
    _remove_comments()     - Config'den yorum satırlarını temizler (helper)
    _validate_config_syntax() - Config syntax kontrolü (bonus)

Parse İşlemi:
    1. Config dosyası okunur
    2. Yorumlar temizlenir
    3. Her kural için regex match yapılır
    4. Match bulunursa parser ile parse edilir
    5. Parse edilen değer SSHAudit'e atanır
    6. Validator ile kontrol edilir
    7. Öneri varsa listeye eklenir

Author: ozturu68
Version: 0.5.0
Date: 2025-11-01
License: MIT
"""

import re
import logging
from pathlib import Path
from typing import Optional, Any, List, Tuple

# Local imports
from .rules import SSHConfigRule, SSH_CONFIG_RULES
from ..models import SSHAudit

# Logger
log = logging.getLogger(__name__)


# =============================================================================
# CONFIG OKUMA
# =============================================================================

def _read_ssh_config(config_path: Path) -> Optional[str]:
    """
    SSH config dosyasını okur.
    
    Args:
        config_path: SSH config dosya yolu
            Genellikle: /etc/ssh/sshd_config
    
    Returns:
        Optional[str]: Dosya içeriği veya None (hata durumunda)
    
    Raises:
        ValueError: Dosya bulunamadı veya dosya değil
        PermissionError: Okuma yetkisi yok
        Exception: Diğer okuma hataları
    
    Examples:
        >>> from pathlib import Path
        >>> 
        >>> # Normal kullanım
        >>> config = _read_ssh_config(Path("/etc/ssh/sshd_config"))
        >>> print(len(config))
        2048
        >>> 
        >>> # Hata durumu
        >>> try:
        ...     config = _read_ssh_config(Path("/nonexistent"))
        ... except ValueError as e:
        ...     print(f"Hata: {e}")
        Hata: SSH config dosyası bulunamadı: /nonexistent
    
    Note:
        - Dosya UTF-8 encoding ile okunur
        - Sudo yetkisi gerekebilir
        - Hata durumunda exception raise eder
    """
    # Dosya var mı?
    if not config_path.exists():
        raise ValueError(f"SSH config dosyası bulunamadı: {config_path}")
    
    # Dosya mı?
    if not config_path.is_file():
        raise ValueError(f"SSH config bir dosya değil: {config_path}")
    
    try:
        # UTF-8 encoding ile oku
        content = config_path.read_text(encoding='utf-8')
        log.debug(f"SSH config okundu: {len(content)} byte")
        return content
    
    except PermissionError:
        log.warning(f"SSH config okuma yetkisi yok: {config_path}")
        raise
    
    except Exception as e:
        log.error(f"SSH config okuma hatası: {e}", exc_info=True)
        raise


# =============================================================================
# CONFIG PARSE
# =============================================================================

def _parse_ssh_setting(
    config_content: str,
    rule: SSHConfigRule
) -> Optional[Any]:
    """
    SSH ayarını config içeriğinden parse eder.
    
    Verilen kural için config'de regex match yapar ve parse eder.
    
    Args:
        config_content: SSH config dosya içeriği
        rule: Parse kuralı (SSHConfigRule)
    
    Returns:
        Optional[Any]: Parse edilen değer veya None
            - None: Ayar config'de yok
            - Any: Parse edilmiş değer (bool, str, int vb.)
    
    Examples:
        >>> config = '''
        ... Port 22
        ... PermitRootLogin no
        ... PasswordAuthentication yes
        ... '''
        >>> 
        >>> from security.ssh.rules import SSH_CONFIG_RULES
        >>> root_rule = SSH_CONFIG_RULES[0]  # PermitRootLogin
        >>> 
        >>> value = _parse_ssh_setting(config, root_rule)
        >>> print(value)
        False  # "no" → False
    
    Note:
        - Regex case-insensitive ve multiline
        - İlk match alınır (birden fazla varsa)
        - Parser exception'ı yakalanır ve log'lanır
    """
    # Regex pattern compile et (case-insensitive + multiline)
    pattern = re.compile(rule.pattern, re.MULTILINE | re.IGNORECASE)
    
    # Config'de ara
    match = pattern.search(config_content)
    
    if not match:
        # Ayar config'de yok
        log.debug(f"SSH ayar bulunamadı: {rule.name}")
        return None
    
    # Match'in ilk grubu değeri içerir
    raw_value = match.group(1).strip()
    log.debug(f"SSH ayar bulundu: {rule.name} = {raw_value}")
    
    try:
        # Parser ile parse et
        parsed_value = rule.parser(raw_value)
        log.debug(f"SSH ayar parse edildi: {rule.name} = {parsed_value} (type: {type(parsed_value).__name__})")
        return parsed_value
    
    except Exception as e:
        log.warning(
            f"SSH ayar parse hatası: {rule.name} = {raw_value} ({e})"
        )
        return None


def _apply_ssh_rules(
    config_content: str,
    audit_result: SSHAudit
) -> None:
    """
    Tüm SSH kurallarını uygular.
    
    SSH_CONFIG_RULES listesindeki tüm kuralları sırayla uygular:
        1. Config'den parse et
        2. SSHAudit field'ına ata
        3. Validate et
        4. Öneri varsa ekle
    
    Args:
        config_content: SSH config dosya içeriği
        audit_result: Doldurulacak audit sonucu (in-place değişir)
    
    Note:
        audit_result in-place değiştirilir.
        Kurallar sırayla işlenir (SSH_CONFIG_RULES sırası).
    
    Examples:
        >>> config = _read_ssh_config(Path("/etc/ssh/sshd_config"))
        >>> audit = SSHAudit(config_exists=True, port='22')
        >>> 
        >>> _apply_ssh_rules(config, audit)
        >>> 
        >>> # Sonuç audit'te
        >>> print(audit.root_login_permitted)
        False
        >>> print(audit.recommendations)
        ['⚠️  Şifre ile giriş aktif...']
    """
    log.info(f"SSH kuralları uygulanıyor: {len(SSH_CONFIG_RULES)} kural")
    
    for rule in SSH_CONFIG_RULES:
        try:
            # 1. Config'den parse et
            value = _parse_ssh_setting(config_content, rule)
            
            # 2. Field'ı set et
            if value is not None:
                # Parse edildi, ata
                setattr(audit_result, rule.field_name, value)
                log.debug(f"SSH field set: {rule.field_name} = {value}")
            elif rule.default_value is not None:
                # Parse edilemedi ama varsayılan var
                setattr(audit_result, rule.field_name, rule.default_value)
                log.debug(f"SSH field default: {rule.field_name} = {rule.default_value}")
            else:
                # Parse edilemedi ve varsayılan yok, None kalsın
                log.debug(f"SSH field None: {rule.field_name}")
            
            # 3. Validate et
            current_value = getattr(audit_result, rule.field_name, None)
            
            # Zorunlu ayar kontrolü
            if rule.is_required and current_value is None:
                recommendation = (
                    f"⚠️  {rule.name} ayarı tanımlanmamış (KRİTİK ayar). "
                    f"Kontrol edin!"
                )
                audit_result.add_recommendation(recommendation)
                log.warning(f"SSH zorunlu ayar eksik: {rule.name}")
            
            # Validator çalıştır
            recommendation = rule.validator(current_value, audit_result)
            if recommendation:
                audit_result.add_recommendation(recommendation)
                log.info(f"SSH öneri: {rule.name} → {recommendation[:50]}...")
        
        except Exception as e:
            log.error(
                f"SSH kural uygulama hatası: {rule.name} - {e}",
                exc_info=True
            )
            audit_result.add_recommendation(
                f"⚠️  {rule.name} ayarı kontrol edilemedi: {str(e)}"
            )
    
    # Genel değerlendirme
    if not audit_result.recommendations:
        audit_result.add_recommendation(
            "✅ SSH yapılandırması güvenli görünüyor."
        )
        log.info("SSH yapılandırması güvenli")
    else:
        log.info(f"SSH yapılandırması: {len(audit_result.recommendations)} öneri")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================

def _parse_yes_no(value: str) -> bool:
    """
    yes/no string'ini boolean'a çevirir (helper).
    
    Args:
        value: "yes", "no", "true", "false" vb.
    
    Returns:
        bool: True (yes/true) veya False (no/false)
    
    Examples:
        >>> _parse_yes_no("yes")
        True
        >>> _parse_yes_no("no")
        False
        >>> _parse_yes_no("YES")
        True
        >>> _parse_yes_no("true")
        True
    
    Note:
        Case-insensitive.
        yes/true/1 → True
        no/false/0 → False
    """
    value_lower = value.lower().strip()
    
    if value_lower in ('yes', 'true', '1', 'on'):
        return True
    elif value_lower in ('no', 'false', '0', 'off'):
        return False
    else:
        # Varsayılan: False
        log.warning(f"Bilinmeyen yes/no değeri: {value}, varsayılan: False")
        return False


def _normalize_config(config_content: str) -> str:
    """
    Config içeriğini normalize eder (helper).
    
    - Yorumları temizler
    - Boş satırları temizler
    - Whitespace'leri düzeltir
    
    Args:
        config_content: Ham config içeriği
    
    Returns:
        str: Normalize edilmiş config
    
    Examples:
        >>> config = '''
        ... # Bu yorum
        ... Port 22  # inline yorum
        ... 
        ...   PermitRootLogin no
        ... '''
        >>> 
        >>> normalized = _normalize_config(config)
        >>> print(normalized)
        Port 22
        PermitRootLogin no
    """
    lines = []
    
    for line in config_content.split('\n'):
        # Yorum temizle (# sonrasını sil)
        if '#' in line:
            line = line.split('#')[0]
        
        # Whitespace temizle
        line = line.strip()
        
        # Boş satır atla
        if not line:
            continue
        
        lines.append(line)
    
    return '\n'.join(lines)


def _remove_comments(config_content: str) -> str:
    """
    Config'den yorum satırlarını temizler (helper).
    
    Args:
        config_content: Ham config içeriği
    
    Returns:
        str: Yorumsuz config
    
    Examples:
        >>> config = '''
        ... # Tam satır yorum
        ... Port 22  # inline yorum
        ... PermitRootLogin no
        ... '''
        >>> 
        >>> clean = _remove_comments(config)
        >>> print(clean)
        Port 22
        PermitRootLogin no
    """
    lines = []
    
    for line in config_content.split('\n'):
        # Tam satır yorum mu?
        if line.strip().startswith('#'):
            continue
        
        # Inline yorum var mı?
        if '#' in line:
            line = line.split('#')[0]
        
        lines.append(line)
    
    return '\n'.join(lines)


def _validate_config_syntax(config_content: str) -> Tuple[bool, List[str]]:
    """
    SSH config syntax'ını kontrol eder (bonus fonksiyon).
    
    Temel syntax hatalarını tespit eder:
        - Geçersiz direktifler
        - Format hataları
        - Duplikasyon
    
    Args:
        config_content: SSH config içeriği
    
    Returns:
        Tuple[bool, List[str]]: (geçerli_mi, hata_listesi)
            - True, []: Syntax geçerli
            - False, ["hata1", "hata2"]: Syntax hataları var
    
    Examples:
        >>> config = "Port 22\\nPermitRootLogin no\\n"
        >>> valid, errors = _validate_config_syntax(config)
        >>> print(valid)
        True
        >>> 
        >>> bad_config = "InvalidDirective yes\\n"
        >>> valid, errors = _validate_config_syntax(bad_config)
        >>> print(valid)
        False
        >>> print(errors)
        ['Unknown directive: InvalidDirective']
    
    Note:
        Bu basit bir syntax check'tir.
        Tam kontrol için: sudo sshd -t
    """
    errors = []
    
    # Bilinen SSH direktifleri (basitleştirilmiş liste)
    known_directives = {
        'Port', 'Protocol', 'ListenAddress',
        'PermitRootLogin', 'PasswordAuthentication', 'PermitEmptyPasswords',
        'PubkeyAuthentication', 'AuthorizedKeysFile',
        'X11Forwarding', 'PermitUserEnvironment',
        'MaxAuthTries', 'MaxSessions', 'MaxStartups',
        'LoginGraceTime', 'ClientAliveInterval', 'ClientAliveCountMax',
        'UsePAM', 'UseDNS', 'PrintMotd', 'PrintLastLog',
        'TCPKeepAlive', 'Compression', 'GatewayPorts',
        'AllowUsers', 'AllowGroups', 'DenyUsers', 'DenyGroups',
        'Subsystem', 'AcceptEnv', 'Banner', 'Match',
        'Ciphers', 'MACs', 'KexAlgorithms', 'HostKey',
        'SyslogFacility', 'LogLevel',
    }
    
    # Direktif sayacı (duplikasyon kontrolü)
    directive_counts: dict = {}
    
    for line_num, line in enumerate(config_content.split('\n'), 1):
        # Yorum ve boş satırları atla
        line = line.strip()
        if not line or line.startswith('#'):
            continue
        
        # Direktif parse et
        parts = line.split(None, 1)  # İlk whitespace'de böl
        if not parts:
            continue
        
        directive = parts[0]
        
        # Bilinen direktif mi?
        if directive not in known_directives:
            errors.append(f"Line {line_num}: Unknown directive '{directive}'")
        
        # Duplikasyon kontrolü (bazı direktifler çoklu olabilir)
        multi_allowed = {'ListenAddress', 'HostKey', 'AcceptEnv', 'Subsystem', 'Match'}
        
        if directive not in multi_allowed:
            directive_counts[directive] = directive_counts.get(directive, 0) + 1
            if directive_counts[directive] > 1:
                errors.append(
                    f"Line {line_num}: Duplicate directive '{directive}' "
                    f"(appears {directive_counts[directive]} times)"
                )
    
    # Sonuç
    valid = len(errors) == 0
    return valid, errors


def get_config_diff(old_config: str, new_config: str) -> List[str]:
    """
    İki config arasındaki farkı gösterir (bonus fonksiyon).
    
    Args:
        old_config: Eski config içeriği
        new_config: Yeni config içeriği
    
    Returns:
        List[str]: Değişiklik satırları
    
    Examples:
        >>> old = "Port 22\\nPermitRootLogin yes\\n"
        >>> new = "Port 2222\\nPermitRootLogin no\\n"
        >>> 
        >>> diff = get_config_diff(old, new)
        >>> for line in diff:
        ...     print(line)
        - Port 22
        + Port 2222
        - PermitRootLogin yes
        + PermitRootLogin no
    
    Note:
        Basit line-by-line diff.
        Gerçek diff için difflib kullanabilirsiniz.
    """
    import difflib
    
    old_lines = old_config.split('\n')
    new_lines = new_config.split('\n')
    
    diff = difflib.unified_diff(
        old_lines,
        new_lines,
        lineterm='',
        fromfile='old_sshd_config',
        tofile='new_sshd_config'
    )
    
    return list(diff)


def extract_includes(config_content: str) -> List[str]:
    """
    Config'deki Include direktiflerini çıkarır (bonus).
    
    Args:
        config_content: SSH config içeriği
    
    Returns:
        List[str]: Include dosya yolları
    
    Examples:
        >>> config = '''
        ... Port 22
        ... Include /etc/ssh/sshd_config.d/*.conf
        ... PermitRootLogin no
        ... '''
        >>> 
        >>> includes = extract_includes(config)
        >>> print(includes)
        ['/etc/ssh/sshd_config.d/*.conf']
    
    Note:
        Include dosyaları otomatik parse edilmez (TODO).
    """
    pattern = re.compile(r'^\s*Include\s+(.+)$', re.MULTILINE | re.IGNORECASE)
    matches = pattern.findall(config_content)
    return [match.strip() for match in matches]


# =============================================================================
# MODULE METADATA
# =============================================================================

__all__ = [
    '_read_ssh_config',
    '_parse_ssh_setting',
    '_apply_ssh_rules',
    '_parse_yes_no',
    '_normalize_config',
    '_remove_comments',
    '_validate_config_syntax',
    'get_config_diff',
    'extract_includes',
]